/*
 * Offline check of the UniFi decoders against the captured samples.
 *
 * Replicates the parts of analysisd that decide whether a decoder fires:
 * pre-decoding, the program_name list split, the parent/child topology and the
 * chained sibling decoders - analysisd walks the whole same-name chain and
 * applies every regex that matches, so this does the same.
 *
 * Every UniFi event reaches the decoders with program_name = NULL, which is the
 * opposite of the ExtremeXOS case and the reason pre-decoding is modelled here
 * character by character rather than with a convenient regex: the exact point
 * at which cleanevent.c gives up is what puts these events in the list this
 * ruleset lives in.
 *
 * Checks performed:
 *   - the XML uses an escaping the Wazuh reader accepts for "<"
 *   - pre-decoding really does yield program_name = NULL for every sample, so
 *     the parents are in the list they claim to be in
 *   - the parents are mutually exclusive, since they share one list and
 *     analysisd stops at the first prematch that matches
 *   - every child regex compiles and exposes exactly as many groups as <order>
 *   - no optional capture group is followed by another capture
 *   - every sample line is decoded, and reaches the fields its family
 *     guarantees
 *   - no two decoders set the same field on one line, which would mean the
 *     patterns are not mutually exclusive
 *   - rules reference no field a decoder never sets, ids are unique, and no
 *     rule is shadowed by a higher-level sibling
 *
 * Usage: node scripts/simulate-decode.mjs [--verbose] [--inventory]
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const FAMILIES = [
  {
    parent: "unifi-device",
    externalParent: "symantec-av",
    decoders: "decoders/0100-unifi_device_decoders.xml",
    rules: "rules/0100-unifi_device_rules.xml",
    ruleRange: [100100, 100199],
    // Set by the header child, which must match every line of the family.
    guaranteed: ["unifi.mac", "unifi.daemon", "unifi.message"],
  },
  {
    parent: "unifi-os",
    decoders: "decoders/0101-unifi_os_decoders.xml",
    rules: "rules/0101-unifi_os_rules.xml",
    ruleRange: [109300, 109399],
    // A firewall line has no daemon and a daemon line has no rule identity, so
    // the only field both shapes share is the console name.
    guaranteed: ["unifi.system_name"],
  },
];

const SAMPLES = [
  "samples/unifi-tcpdump.log",
  "samples/unifi-syslog.log",
  "samples/unifi-synthetic.log",
];

const verbose = process.argv.includes("--verbose");
const inventory = process.argv.includes("--inventory");

/* ------------------------------------------------------------------ */
/* Pre-decoding, after src/analysisd/cleanevent.c                      */
/* ------------------------------------------------------------------ */

/*
 * hostname_map in src/os_regex/os_regex_maps.c marks a character valid by
 * holding 1 at its index. Reading the table out: letters, digits, "_", "-",
 * ".", "/", "@", "(" and ")" are valid; space, ",", "+", ":", "[" and "|" are
 * not. The comma is what breaks UniFi: it stops the program-name walk at a
 * character none of the accepted formats expect.
 */
const isValidChar = (c) => c !== undefined && /[A-Za-z0-9_\-./@()]/.test(c);

/*
 * Returns { hostname, program, log } the way OS_CleanMSG would, for an RFC 3164
 * body that has already had its priority stripped by remoted.
 */
function preDecode(rest) {
  let i = 0;
  while (isValidChar(rest[i])) i++;

  // Syslog without a hostname, the Solaris shape: "p_name: message".
  if (rest[i] === ":" && rest[i + 1] === " ") {
    return { hostname: null, program: rest.slice(0, i), log: rest.slice(i + 2) };
  }
  // Invalid hostname: analysisd keeps the whole remainder as the log.
  if (rest[i] !== " ") return { hostname: null, program: null, log: rest };

  const hostname = rest.slice(0, i);
  const body = rest.slice(i + 1);

  let j = 0;
  while (isValidChar(body[j])) j++;

  // "p_name:" - the space after the colon is optional.
  if (body[j] === ":") {
    let k = j + 1;
    if (body[k] === " ") k++;
    return { hostname, program: body.slice(0, j), log: body.slice(k) };
  }
  // "p_name[pid]:" - only when what follows the bracket is a digit.
  if (body[j] === "[" && /\d/.test(body[j + 1] ?? "")) {
    let k = j + 2;
    while (/\d/.test(body[k] ?? "")) k++;
    if (body[k] === "]" && body[k + 1] === ":") {
      k += 2;
      if (body[k] === " ") k++;
      return { hostname, program: body.slice(0, j), log: body.slice(k) };
    }
  }
  // Everything else falls through to the last else branch: no program name,
  // and the log keeps everything after the hostname.
  return { hostname, program: null, log: body };
}

/*
 * The capture is "tcpdump -A" output, so a datagram starts at its priority
 * partway through a line of packet bytes. The curated files hold the line as
 * remoted delivers it, with the priority already gone.
 */
const WITH_PRI = /<\d+>(\w{3}\s+\d+\s\d\d:\d\d:\d\d\s.*)$/;
const WITHOUT_PRI = /^(\w{3}\s+\d+\s\d\d:\d\d:\d\d\s.*)$/;

const stripHeader = (line) => {
  const m = WITH_PRI.exec(line) ?? WITHOUT_PRI.exec(line);
  if (!m) return null;
  // Drop the "Mmm dd HH:MM:SS " that pre-decoding consumes before the hostname.
  return m[1].replace(/^\w{3}\s+\d+\s\d\d:\d\d:\d\d\s/, "");
};

/* ------------------------------------------------------------------ */
/* PCRE2 and the Wazuh XML reader                                      */
/* ------------------------------------------------------------------ */

/*
 * PCRE2 constructs these files rely on that JS spells differently: \x{3C} is
 * only valid under the /u flag, which would change other escapes, and JS has no
 * scoped (?i:...) groups.
 */
function pcre2ToJs(pattern) {
  return pattern
    .replace(/\\x\{([0-9A-Fa-f]+)\}/g, (_m, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\(\?i:(\(?)([A-Za-z]+)(\)?)\)/g, (_m, open, word, close) => {
      const expanded = [...word].map((ch) => `[${ch.toLowerCase()}${ch.toUpperCase()}]`).join("");
      return `${open}${expanded}${close}`;
    });
}

/*
 * The Wazuh XML reader ends element content at a "<" unless a backslash
 * suppresses it, and it understands neither &lt; nor CDATA. Anything else is a
 * load-time XMLERR that takes down the whole ruleset, not just this file.
 */
function checkAngleBrackets(xml, file) {
  const found = [];
  xml.split(/\r?\n/).forEach((line, i) => {
    const m = /^\s*<(prematch|regex|program_name|order)(?:\s[^>]*)?>(.*)<\/\1>\s*$/.exec(line);
    if (!m) return;
    const content = m[2];
    if (/&lt;|&gt;|<!\[CDATA\[/.test(content)) {
      found.push(`${file}:${i + 1}: entity or CDATA in <${m[1]}> is not decoded by Wazuh`);
    }
    for (let j = 0; j < content.length; j++) {
      if (content[j] === "<" && content[j - 1] !== "\\") {
        found.push(`${file}:${i + 1}: unescaped "<" in <${m[1]}>, write it as \\x{3C}`);
        break;
      }
    }
  });
  return found;
}

/*
 * Wazuh reads PCRE2 groups only up to the highest one that took part in the
 * match, and reads a group that did not take part from an unset offset. So an
 * optional group containing a capture is only safe when no further capture
 * follows it. An optional group with no capture inside does not shift
 * numbering and is always fine.
 */
function optionalCaptureNotLast(pattern) {
  const stack = [];
  let optionalCaptureSeen = false;
  let inClass = false;

  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      continue;
    }
    if (c === "[") {
      inClass = true;
    } else if (c === "(") {
      const capturing = pattern[i + 1] !== "?";
      if (capturing && optionalCaptureSeen) return pattern.slice(i, i + 24);
      stack.push({ capturing, hasCapture: capturing });
    } else if (c === ")") {
      const group = stack.pop() ?? { hasCapture: false };
      if (stack.length) stack.at(-1).hasCapture ||= group.hasCapture;
      const quantifier = pattern[i + 1];
      if ((quantifier === "?" || quantifier === "*") && group.hasCapture) {
        optionalCaptureSeen = true;
      }
    }
  }
  return null;
}

const countGroups = (rx) => new RegExp(`${rx.source}|`).exec("").length - 1;

function parseDecoders(xml) {
  const decoders = [];
  for (const m of xml.matchAll(/<decoder name="([^"]+)">([\s\S]*?)<\/decoder>/g)) {
    const [, name, body] = m;
    // The comment block immediately above this decoder, if there is one.
    // The greedy prefix is what pins this to the *last* comment before the
    // decoder; a lazy body alone would stretch from the file header instead.
    const before = xml.slice(0, m.index);
    const lastComment = /[\s\S]*<!--([\s\S]*?)-->\s*$/.exec(before);
    const node = { name, order: [], comment: lastComment?.[1] };
    for (const [, tag, type, value] of body.matchAll(
      /<(\w+)(?:\s+type="(\w+)")?>([\s\S]*?)<\/\1>/g,
    )) {
      const v = value.trim();
      if (tag === "order") node.order = v.split(",").map((f) => f.trim());
      else {
        node[tag] = v;
        node[`${tag}Type`] = type ?? "osregex";
      }
    }
    decoders.push(node);
  }
  return decoders;
}

/*
 * Every child shares its parent's name so that analysisd chains them, which
 * leaves nothing in the XML to tell them apart. The comment above each decoder
 * carries the message format it was written for, so its first line is the
 * label - derived from the file rather than guessed from the pattern.
 */
function labelOf(comment, index) {
  const first = (comment ?? "")
    .split(/\r?\n/)
    .map((l) => l.replace(/^\s*/, ""))
    .find((l) => l.length > 0 && !/^=+$/.test(l));
  if (!first) return `pattern #${index}`;
  return first.replace(/\s+$/, "").slice(0, 74);
}

/* ------------------------------------------------------------------ */
/* Load                                                                */
/* ------------------------------------------------------------------ */

const problems = [];
const xmlProblems = [];

for (const family of FAMILIES) {
  const xml = readFileSync(join(root, family.decoders), "utf8");
  xmlProblems.push(...checkAngleBrackets(xml, family.decoders));

  const nodes = parseDecoders(xml);
  // Reject grandchildren exactly as OS_AddOSDecoder does: it searches parent
  // names only in the two root lists, never inside another node's child list.
  // A name shared by a root and its children is valid (the standard sibling
  // pattern); a name found only on children cannot itself be referenced.
  for (const node of nodes.filter((d) => d.parent)) {
    const localParents = nodes.filter((candidate) => candidate.name === node.parent);
    if (localParents.length && localParents.every((candidate) => candidate.parent)) {
      problems.push(
        `${family.decoders}: ${node.name} references child decoder ${node.parent}; ` +
          "Wazuh decoders cannot have grandchildren",
      );
    }
  }

  // unifi-device is a same-name chain of direct children of the stock
  // symantec-av root. unifi-os owns its root and has a conventional child
  // chain. In both cases the entry is the only node allowed a prematch.
  const entry = family.externalParent
    ? nodes.find(
        (d) =>
          d.name === family.parent &&
          d.parent === family.externalParent &&
          d.prematch,
      )
    : nodes.find((d) => d.name === family.parent && !d.parent);
  if (!entry) {
    problems.push(`${family.decoders}: no entry decoder named ${family.parent}`);
    continue;
  }
  family.parentNode = entry;
  if (family.parentNode.name !== family.parent) {
    problems.push(`${family.decoders}: parent is "${family.parentNode.name}", expected "${family.parent}"`);
  }
  if (family.parentNode.program_name) {
    problems.push(
      `${family.decoders}: parent declares program_name, but every UniFi event ` +
        "pre-decodes to program_name = NULL and so lives in the other list",
    );
  }

  family.children = family.externalParent
    ? nodes.filter(
        (d) => d.name === family.parent && d.parent === family.externalParent,
      )
    : nodes.filter((d) => d.parent === family.parent);
  if (family.externalParent) {
    const misplaced = nodes.filter(
      (d) => d.name === family.parent && d.parent !== family.externalParent,
    );
    if (misplaced.length) {
      problems.push(
        `${family.decoders}: every ${family.parent} decoder must be a direct ` +
          `child of ${family.externalParent}`,
      );
    }
    if (family.children[0] !== entry) {
      problems.push(
        `${family.decoders}: the prematch+regex entry must be the first ` +
          `${family.parent} child`,
      );
    }
  }
  if (family.externalParent && entry.use_own_name !== "true") {
    problems.push(
      `${family.decoders}: ${family.parent} must set use_own_name=true because ` +
        `its root parent is ${family.externalParent}`,
    );
  }
  if (new Set(family.children.map((c) => c.name)).size !== 1) {
    problems.push(
      `${family.decoders}: children must all share one name so analysisd chains them via get_next`,
    );
  }

  family.compiled = [];
  family.children.forEach((child, i) => {
    child.label = labelOf(child.comment, i);
    if (child.prematch && child !== entry) {
      problems.push(`${child.label}: only the first chained child may declare prematch`);
    }
    if (!child.regex) {
      problems.push(
        `${child.label}: every chained child must declare regex; a prematch-only ` +
          "first child makes Wazuh reject the next same-name decoder as a duplicate",
      );
      return;
    }
    let rx;
    try {
      rx = new RegExp(pcre2ToJs(child.regex));
    } catch (err) {
      problems.push(`${child.label}: regex does not compile: ${err.message}`);
      return;
    }
    const groups = countGroups(rx);
    if (groups !== child.order.length) {
      problems.push(
        `${child.label}: ${groups} capture groups but ${child.order.length} order fields`,
      );
    }
    const offender = optionalCaptureNotLast(child.regex);
    if (offender) {
      problems.push(
        `${child.label}: capture "${offender}" follows an optional capture group, ` +
          "so Wazuh would read it from an unset PCRE2 offset",
      );
    }
    family.compiled.push({ child, rx });
  });

  family.prematchRx = new RegExp(pcre2ToJs(family.parentNode.prematch));
  family.produced = new Set(family.children.flatMap((c) => c.order));
}

/* ------------------------------------------------------------------ */
/* Samples                                                             */
/*                                                                     */
/* Both parents live in the list for events without a program name,     */
/* where analysisd stops at the first prematch that matches. Distinct   */
/* prematches are not enough, so every line records how many parents    */
/* claimed it and more than one is an error.                            */
/* ------------------------------------------------------------------ */

const lines = [];
for (const file of SAMPLES) {
  let text;
  try {
    text = readFileSync(join(root, file), "utf8");
  } catch {
    problems.push(`sample file missing: ${file}`);
    continue;
  }
  for (const raw of text.split(/\r?\n/)) {
    const body = stripHeader(raw.trim());
    if (body) lines.push({ file, body });
  }
}

let total = 0;
let decoded = 0;
const undecoded = [];
const perDecoder = new Map();
const perFamily = new Map();
const firstFields = new Map();
const genericOnly = new Map();
const overlaps = new Set();
// Every decoded line with the fields it ended up with, so the rules can be
// evaluated against real events instead of against a list of event names.
const decodedLines = [];

for (const { body } of lines) {
  const pre = preDecode(body);
  total++;

  if (pre.program !== null) {
    problems.push(
      `pre-decoding produced program_name "${pre.program}", so this event is in ` +
        `the other decoder list and none of these decoders can see it: ${body.slice(0, 90)}`,
    );
    continue;
  }

  const matching = FAMILIES.filter((f) => f.prematchRx.test(pre.log));
  if (matching.length === 0) {
    undecoded.push(["no parent prematch matched", pre.log]);
    continue;
  }
  if (matching.length > 1) {
    overlaps.add(
      `${matching.map((f) => f.parent).join(" and ")} both prematch: ${pre.log.slice(0, 70)}`,
    );
  }
  const family = matching[0];
  perFamily.set(family.parent, (perFamily.get(family.parent) ?? 0) + 1);

  // analysisd applies every regex in the chain, skipping the ones that fail.
  const fields = new Map();
  const matchedBy = [];
  const collisions = [];
  for (const { child, rx } of family.compiled) {
    const hit = rx.exec(pre.log);
    if (!hit) continue;
    matchedBy.push(child.label);
    perDecoder.set(child.label, (perDecoder.get(child.label) ?? 0) + 1);
    child.order.forEach((key, i) => {
      if (hit[i + 1] === undefined) return;
      if (fields.has(key) && fields.get(key) !== hit[i + 1]) {
        collisions.push(`${key} (${child.label})`);
      }
      fields.set(key, hit[i + 1]);
    });
  }

  const missing = family.guaranteed.filter((f) => !fields.has(f));
  if (missing.length) {
    undecoded.push([`${family.parent} set no ${missing.join(", ")}`, pre.log]);
    continue;
  }
  if (collisions.length) {
    problems.push(
      `field set twice on one line: ${collisions.join(", ")} - ${pre.log.slice(0, 80)}`,
    );
  }

  decoded++;
  decodedLines.push({ family: family.parent, fields, body: pre.log });
  if (!fields.has("id")) {
    const key = `${family.parent} / ${fields.get("unifi.daemon") ?? "firewall"}`;
    genericOnly.set(key, (genericOnly.get(key) ?? 0) + 1);
  }
  for (const label of matchedBy) {
    if (!firstFields.has(label)) firstFields.set(label, { body: pre.log, fields: [...fields] });
  }
}

/* ------------------------------------------------------------------ */
/* Rules                                                              */
/* ------------------------------------------------------------------ */

const STATIC_FIELDS = new Set([
  "id", "srcip", "dstip", "srcport", "dstport", "srcuser", "dstuser", "protocol",
  "action", "status", "url", "data", "extra_data", "system_name", "full_log",
  "hostname", "program_name",
]);

const allRuleIds = [];
for (const family of FAMILIES) {
  let ruleXml;
  try {
    ruleXml = readFileSync(join(root, family.rules), "utf8");
  } catch {
    problems.push(`rule file missing: ${family.rules}`);
    continue;
  }
  xmlProblems.push(...checkAngleBrackets(ruleXml, family.rules));

  const ids = [...ruleXml.matchAll(/<rule\s+id="(\d+)"/g)].map((m) => Number(m[1]));
  allRuleIds.push(...ids);
  const [lo, hi] = family.ruleRange;
  for (const id of ids) {
    if (id < lo || id > hi) {
      problems.push(`${family.rules}: rule ${id} is outside the range ${lo}-${hi}`);
    }
  }

  /*
   * rules_op.c rejects a level outside 0-16, and it rejects it at load time for
   * the whole ruleset: wazuh-logtest then answers every line with "Failure to
   * initializing session" and no alerts are produced at all. The message names
   * the level but not the rule, so this check names the rule.
   */
  for (const [, id, level] of ruleXml.matchAll(/<rule\s+id="(\d+)"\s+level="(\d+)"/g)) {
    if (Number(level) > 16) {
      problems.push(
        `${family.rules}: rule ${id} has level ${level}; rules_op.c accepts 0-16 and ` +
          "refuses to load the entire ruleset otherwise",
      );
    }
  }

  const referenced = new Set([
    ...[...ruleXml.matchAll(/\$\(([\w.]+)\)/g)].map((m) => m[1]),
    ...[...ruleXml.matchAll(/<field name="([\w.]+)"/g)].map((m) => m[1]),
  ]);
  for (const f of referenced) {
    if (!family.produced.has(f) && !STATIC_FIELDS.has(f)) {
      problems.push(`${family.rules}: references $(${f}), which no decoder sets`);
    }
  }

  family.ruleXml = ruleXml;
}

const duplicates = allRuleIds.filter((id, i) => allRuleIds.indexOf(id) !== i);
if (duplicates.length) {
  problems.push(`duplicate rule ids: ${[...new Set(duplicates)].join(", ")}`);
}

/*
 * Sibling rules are not evaluated in file order. Before _OS_AddRule inserts a
 * level-0 rule it temporarily changes its level to 99, then orders siblings by
 * descending level; the displayed level is restored later. File position only
 * breaks ties. This gives silencing rules highest matching priority, and makes
 * an unconditional level-0 catch-all shadow every nonzero sibling.
 *
 * The check runs against the lines that were actually decoded rather than
 * against a list of event names, because a rule can also select on
 * unifi.daemon or on a substring of the message, and a shadowing bug in those
 * is just as silent.
 */
function compileRulePattern(pattern) {
  const inline = /^\(\?i\)/.test(pattern);
  return new RegExp(pcre2ToJs(pattern.replace(/^\(\?i\)/, "")), inline ? "i" : "");
}

function parseRule(id, level, body) {
  const conditions = [];
  const regexPattern = /<regex(?:\s+type="\w+")?>([\s\S]*?)<\/regex>/.exec(body);
  if (regexPattern) {
    const rx = compileRulePattern(regexPattern[1].trim());
    conditions.push((_fields, log) => rx.test(log));
  }
  const idPattern = /<id(?:\s+type="\w+")?>([\s\S]*?)<\/id>/.exec(body);
  if (idPattern) {
    const rx = compileRulePattern(idPattern[1].trim());
    conditions.push((fields) => fields.has("id") && rx.test(fields.get("id")));
  }
  for (const [, name, pattern] of body.matchAll(
    /<field name="([\w.]+)"(?:\s+type="\w+")?>([\s\S]*?)<\/field>/g,
  )) {
    const rx = compileRulePattern(pattern.trim());
    conditions.push((fields) => fields.has(name) && rx.test(fields.get(name)));
  }
  const matchPattern = /<match>([\s\S]*?)<\/match>/.exec(body);
  if (matchPattern) {
    // <match> is an OR of pipe-separated substrings, case sensitive.
    const needles = matchPattern[1].trim().split("|");
    conditions.push((_fields, log) => needles.some((n) => log.includes(n)));
  }
  return { id, level: Number(level), conditions };
}

const ruleChoice = new Map();
for (const family of FAMILIES) {
  if (!family.ruleXml) continue;
  const base = family.ruleRange[0];

  const siblings = [];
  const blocks = family.ruleXml.matchAll(
    /<rule\s+id="(\d+)"\s+level="(\d+)"([^>]*)>([\s\S]*?)<\/rule>/g,
  );
  for (const [, id, level, attrs, rbody] of blocks) {
    // A correlation rule fires off an already-matched sibling, so it does not
    // take part in this competition.
    if (/frequency=/.test(attrs) || /<if_matched_sid>/.test(rbody)) continue;
    const ifSid = /<if_sid>(\d+)<\/if_sid>/.exec(rbody);
    if (!ifSid || Number(ifSid[1]) !== base) continue;
    siblings.push(parseRule(id, level, rbody));
  }
  if (!siblings.length) continue;

  const evaluationOrder = siblings
    .map((rule, position) => ({
      ...rule,
      position,
      loadPriority: rule.level === 0 ? 99 : rule.level,
    }))
    .sort((a, b) => b.loadPriority - a.loadPriority || a.position - b.position);

  const familyLines = decodedLines.filter((l) => l.family === family.parent);
  const matches = (rule, fields, log) => rule.conditions.every((c) => c(fields, log));
  const matchCount = (rule) => familyLines.filter((l) => matches(rule, l.fields, l.body)).length;
  // The catch-all is whichever sibling matches the broadest set of lines;
  // naming it by number here would go stale the moment the ids are renumbered.
  const generic = [...siblings].sort((a, b) => matchCount(b) - matchCount(a))[0];

  for (const { fields, body } of familyLines) {
    const candidates = evaluationOrder.filter((r) => matches(r, fields, body));
    if (!candidates.length) continue;
    const key = `${family.parent} ${fields.get("id") ?? `(${fields.get("unifi.daemon") ?? "firewall"})`}`;
    ruleChoice.set(key, `${candidates[0].id} (level ${candidates[0].level})`);
    if (generic && candidates.length > 1 && candidates[0].id === generic.id) {
      problems.push(
        `rule ${generic.id} (level ${generic.level}) shadows ` +
          `${candidates.slice(1).map((r) => `${r.id} (level ${r.level})`).join(", ")} for ` +
          `"${key}": a sibling with a higher level is evaluated first`,
      );
    }
  }
}

/* ------------------------------------------------------------------ */
/* Report                                                             */
/* ------------------------------------------------------------------ */

if (inventory) {
  const byDaemon = new Map();
  for (const { body } of lines) {
    const pre = preDecode(body);
    const family = FAMILIES.find((f) => f.prematchRx.test(pre.log));
    if (!family) continue;
    let daemon = "(firewall)";
    for (const { child, rx } of family.compiled) {
      const i = child.order.indexOf("unifi.daemon");
      if (i === -1) continue;
      const hit = rx.exec(pre.log);
      if (hit?.[i + 1]) {
        daemon = hit[i + 1];
        break;
      }
    }
    const key = `${family.parent} / ${daemon}`;
    byDaemon.set(key, (byDaemon.get(key) ?? 0) + 1);
  }
  console.log(`daemons found in the samples (${byDaemon.size} distinct):\n`);
  for (const [k, c] of [...byDaemon].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(c).padStart(4)}  ${k}`);
  }
  console.log();
}

if (xmlProblems.length) {
  console.log("XML PROBLEMS");
  for (const p of xmlProblems) console.log("  -", p);
  console.log();
}
if (overlaps.size) {
  console.log("PARENT PREMATCH OVERLAP");
  for (const o of overlaps) console.log("  -", o);
  console.log();
}
if (problems.length) {
  console.log("STRUCTURAL PROBLEMS");
  for (const p of [...new Set(problems)]) console.log("  -", p);
  console.log();
}

const childCount = FAMILIES.reduce((n, f) => n + (f.children?.length ?? 0), 0);
console.log(`decoded ${decoded}/${total} sample lines with ${childCount} chained decoders`);
console.log(`checked ${allRuleIds.length} rules across ${FAMILIES.length} families`);
for (const [parent, count] of perFamily) console.log(`  ${String(count).padStart(4)}  ${parent}`);

if (undecoded.length) {
  console.log(`\nUNDECODED (${undecoded.length})`);
  for (const [reason, body] of undecoded.slice(0, 25)) {
    console.log(`  [${reason}] ${body.slice(0, 110)}`);
  }
}

if (genericOnly.size) {
  console.log("\nno specific decoder, header fields only:");
  for (const [k, c] of [...genericOnly].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(c).padStart(4)}  ${k}`);
  }
}

console.log("\nlines per decoder:");
for (const [label, count] of [...perDecoder].sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(count).padStart(4)}  ${label}`);
}

const unused = FAMILIES.flatMap((f) => (f.compiled ?? []).map((c) => c.child.label)).filter(
  (label) => !perDecoder.has(label),
);
if (unused.length) console.log(`\nno sample exercises: ${unused.join(", ")}`);

if (verbose) {
  console.log("\nrule that wins per id (level 0 loads as priority 99):");
  for (const [tag, rule] of [...ruleChoice].sort((a, b) => a[0].localeCompare(b[0]))) {
    console.log(`  ${tag.padEnd(46)} ${rule}`);
  }
  console.log("\nfields extracted (first line per decoder):");
  for (const [label, { body, fields }] of firstFields) {
    console.log(`\n  ${label}`);
    console.log(`    log: ${body.slice(0, 150)}`);
    for (const [key, value] of fields) console.log(`    ${key} = ${value}`);
  }
}

process.exit(xmlProblems.length || problems.length || overlaps.size || undecoded.length ? 1 : 0);

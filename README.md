# Ubiquiti UniFi — Wazuh decoders

Custom Wazuh decoders and rules for **UniFi** access points, switches and UniFi OS consoles, over syslog UDP/514.

Rule IDs: **100100–100199** (UniFi APs and switches) and **109300–109399** (UniFi OS consoles), both below the **110100–110199** range used by the [ExtremeXOS ruleset](https://github.com/oliwier-drop/Extreme-Networks-Wazuh-Decoders). 100000–100500 is left alone: that is where `local_rules.xml` from Wazuh tutorials lands, and a duplicate sid is skipped without a load error.

Copy the files into the manager user directories so upgrades do not overwrite them. UniFi AP/switch lines look like Symantec CSV to the stock decoder (`symantec-av` / rule 7300) — see [Symantec](#the-stock-symantec-decoder-steals-every-ap-and-switch-line). The UniFi device decoder is a child of that parent, so the stock file can stay loaded.

## Layout

| Path | Destination on the Wazuh manager |
| --- | --- |
| `decoders/0100-unifi_device_decoders.xml` | `/var/ossec/etc/decoders/` |
| `decoders/0101-unifi_os_decoders.xml` | `/var/ossec/etc/decoders/` |
| `decoders/0330-symantec_decoders.xml` | **do not copy** unless you also receive real Symantec AV CSV; see Symantec section |
| `rules/0100-unifi_device_rules.xml` | `/var/ossec/etc/rules/` |
| `rules/0101-unifi_os_rules.xml` | `/var/ossec/etc/rules/` |
| `samples/unifi-tcpdump.log` | raw `tcpdump -A` capture (reference only) |
| `samples/unifi-syslog.log` | input for `wazuh-logtest`, one line per format seen in the capture |
| `samples/unifi-synthetic.log` | input for `wazuh-logtest`, formats absent from the capture |
| `scripts/simulate-decode.mjs` | offline check of the decoders against every sample |

## Three device families, one decoder list

The capture holds three shapes, and they are not variations of one format — they differ in where the device identity sits, which is exactly what pre-decoding keys on.

**Access point.** The device prefixes every message with its own MAC and firmware:

```
<14>Aug 20 09:11:17 U7-Pro-Outdoor 9041b21628d1,U7-Pro-Outdoor-8.6.11+18870: hostapd[13361]: wifi1ap4: AP-STA-CONNECTED 22:94:04:5f:25:58
```

**Switch.** Same prefix, plus an extra slot before the daemon holding `switch`, or nothing at all:

```
<29>Aug 20 09:11:19 USW-AG2-CORE 58d61f76e868,USW-Pro-Aggregation-7.4.1+16850: switch: TRAPMGR: Link Down: 0/5
<14>Aug 20 09:11:14 USW-WIFI-H3 74fa294b1192,USW-Pro-Max-24-PoE-7.5.10+17129: : ubnt-fanctrl[943]: fanctrl.fanctrl_log(): Fan speed 25% ...
```

**UniFi OS console.** No MAC prefix; instead the console repeats its own hostname:

```
<13>Aug 20 09:12:01 UDM-Pro-Max-Prime UDM-Pro-Max-Prime [WAN_LAN-A-10001] DESCR="PA_LibreNMS_to_OT-MGMT" IN=eth9 OUT=br0 MAC=... SRC=10.248.162.51 DST=10.248.188.103 ...
<30>Aug 20 09:12:02 UDM-Pro-Max-Prime UDM-Pro-Max-Prime mcad[3735297]: ui-probe-dhcpv6: sending Solicit on eth9
```

### What the decoders actually receive

`wazuh-remoted` strips the priority, so `<14>` never reaches the ruleset. Pre-decoding then splits the header — and on every one of the 151 datagrams in the capture, **it fails to find a program name**. That single fact shapes both decoder files.

`cleanevent.c` walks the program-name candidate with `isValidChar()`, whose `hostname_map` in `os_regex_maps.c` holds 1 for a valid character. Reading the table out: letters, digits, `_ - . / @ ( )` are valid; **space, `,`, `+`, `:`, `[` are not**. The three families each stop the walk on a character none of the accepted formats (`p_name:`, `p_name[pid]:`, AIX `facility:severity p_name:`) expects, so control reaches the final `else` and sets `program_name = NULL`, leaving `lf->log` pointing at the whole remainder:

| Family | Candidate | Stops on | Result |
| --- | --- | --- | --- |
| AP / switch | `9041b21628d1` | `,` | `program_name = NULL` |
| UniFi OS | `UDM-Pro-Max-Prime` (the second copy) | space | `program_name = NULL` |

So the decoders see:

```
program_name = (none)
log          = 9041b21628d1,U7-Pro-Outdoor-8.6.11+18870: hostapd[13361]: wifi1ap4: AP-STA-CONNECTED 22:94:04:5f:25:58
```

This is the **opposite** of the ExtremeXOS case, where the parent had to declare `program_name` to be reachable at all. Wazuh keeps decoders with and without `program_name` in separate lists and searches only the one matching the pre-decoded event, so here both parents must leave it out. The compensation is that the device MAC, model, firmware and daemon name all stay inside the body, where a decoder can extract them — fields the Extreme ruleset never had.

### The consequence that matters most for security

Every one of Wazuh's built-in Linux decoders is keyed on `program_name`: `sshd`, `sudo`, `su`, `systemd`, `dropbear`. On a UniFi OS console **none of them can ever fire**, however ordinary the message looks, because the duplicated hostname destroys the program name before any decoder is reached. A console SSH login is not merely unclassified — it is invisible.

That is why `0101-unifi_os_decoders.xml` carries its own `sshd` and `sudo` patterns instead of leaving them to the default ruleset. It is also worth checking, on any Wazuh manager already receiving UniFi traffic, whether console logins have been silently absent from alerts all along.

### Where the patterns come from

Ubiquiti publishes **no equivalent of the ExtremeXOS EMS Message Catalog** — no message list, no event catalogue, no `show log events ... details`. There are three sources instead, in descending order of trustworthiness:

1. **Upstream source code.** UniFi devices run stock `hostapd`, `dnsmasq`, `dropbear` and the netfilter LOG target. Their message texts are fixed in code, which is a better source of truth than a vendor PDF.
2. **The capture in `samples/`.** The only source for the Ubiquiti-proprietary daemons — `stahtd`, `wevent`, `ubnt-fanctrl`, the `switch:` wrapper, and the `UBNT_ROAM` extension to `hostapd`, which is a Ubiquiti patch and does not exist upstream.
3. **Nothing else.** Anything neither captured nor traceable to source is a guess, and the Extreme ruleset has three fixed bugs that were exactly that.

Patterns still awaiting verification against `hostapd` source are listed under [Next samples](#next-samples); `simulate-decode.mjs` names them on every run as `no sample exercises`.

### Five constraints from analysisd

These come from `decoder.c`, `decoders_list.c`, `shared/expression.c` and `os_xml/os_xml.c`. Each fails silently — as "No decoder matched", or as a field that is quietly missing.

**A parent that has children never runs its own `<regex>`.** `DecodeEvent` reassigns its working pointer to a child before reaching the regex stage, so all fields come from the children.

**Children that share one name are chained; children with distinct names are not.** With distinct names, analysisd picks the first child whose `<prematch>` matches and, if that child's regex then fails, drops the event undecoded — the remaining siblings are never tried. With one shared name it sets `get_next`, walks the entire chain, applies every regex that matches and skips those that do not. Every child in a file here shares its parent's name for that reason. Chained children must not declare `<prematch>`.

**Because the whole chain is applied, one child can carry the header for every line.** This is the one place where the UniFi files are simpler than the Extreme ones. A single pattern per family extracts MAC, model, firmware, daemon and message body, and runs on every line; the event patterns then add only their own fields and never repeat the prefix. It also makes the header child a guaranteed fallback: an event whose message text drifts between firmware releases still arrives with its device and daemon attributed instead of vanishing. The price is that patterns must be mutually exclusive per field, or the same field is set twice — which is why the two `sudo` patterns are separated by anchoring the success case on `: TTY=` rather than on the `USER=` both lines contain.

**An optional PCRE2 group is only safe at the end of a pattern.** `w_expression_PCRE2_fill_regex_match` reads groups up to the highest one that took part in the match, and computes each length as `ovector[2i+1] - ovector[2i]`. For a group that did not take part, both offsets are `PCRE2_UNSET`, so the field is read from an unset offset. A trailing optional group is fine — the netfilter `SPT`/`DPT` pair, absent for ICMP, is exactly that case. A group that does not participate *before* one that does is a bug; the RADIUS-timeout decoder originally captured an interface prefix that way and the simulation rejected it.

**Two parents in one list must be mutually exclusive, not merely different.** Both families here live in the list for events without a program name, and analysisd stops at the first parent whose `<prematch>` matches. The first version of the UniFi OS prematch used `^\S+ <daemon>[<pid>]: `, which an access-point line satisfies exactly — `8cede174ee36,U7-Pro-8.7.11+19419: hostapd[13361]: ` — so the console parent silently claimed every AP event. Narrowing the first token to `[\w.-]+`, which cannot contain the `,` or `:` of the device prefix, separates them regardless of the order the files happen to load in. The simulation fails if more than one parent claims a line.

The same first-match rule is why a standalone `unifi-device` parent never runs: the stock Symantec decoder matches first. See the next section.

A literal `<` would need the PCRE2 hex escape `\x{3C}`, because the Wazuh XML reader decodes neither `&lt;` nor CDATA and only honours a backslash suppressing the tag-opening meaning of the next character. No pattern in these files needs one, but the simulation still checks, since the failure mode is a load-time `XMLERR` that takes down the whole ruleset rather than just this file.

### The stock Symantec decoder steals every AP and switch line

This is [wazuh/wazuh-ruleset#840](https://github.com/wazuh/wazuh-ruleset/issues/840), open since 2021. The stock parent is:

```
<prematch>^\w\w\w\w\w\w\w\w\w\w\w\w,</prematch>
```

Twelve word characters and a comma. A UniFi MAC prefix is exactly that (`9041b21628d1,`), the stock file loads from `ruleset/decoders` **before** anything in `etc/decoders`, and analysisd never reaches `unifi-device`. `wazuh-logtest` then reports:

```
**Phase 2: Completed decoding.
        name: 'symantec-av'
**Phase 3: Completed filtering (rules).
        id: '7300'
        description: 'Grouping of Symantec AV rules.'
```

A more specific UniFi prematch does not help: first match wins, not most specific. Excluding the stock file is also brittle on 4.x (`<decoder_exclude>` is silently ignored if the path does not match exactly).

`unifi-device` is therefore a **child of `symantec-av`**, with `<use_own_name>true</use_own_name>` so Phase 2 still reports `unifi-device`. Its own prematch requires the firmware token after the comma (`U7-Pro-8.7.11+19419:`), which real Symantec CSV (`24090D00000A,4,3,7,...`) never has.

That only works if the loaded `symantec-av` parent still has the **stock** prematch. Do **not** copy `0330-symantec_decoders.xml` into `/var/ossec/etc/decoders/` as `symantec_decoders.xml`: that replacement narrows the parent prematch, UniFi no longer matches the parent, and the child never runs. Delete any leftover:

```
sudo rm -f /var/ossec/etc/decoders/symantec_decoders.xml
```

Leave stock `ruleset/decoders/0330-symantec_decoders.xml` loaded. Do not edit it — the next Wazuh upgrade overwrites it.

The replacement file stays in this repo for sites that actually ingest Symantec AV CSV and want both families; that path needs a standalone `unifi-device` parent, which is the combination that failed on this manager.

`wazuh-logtest` talks to analysisd, so **restart wazuh-manager** after changing the XML files; copying them is not enough.

## Sending the logs

In the UniFi Network application, per site: **Settings → System → Logging** (older versions: **Settings → Support → Remote Logging**), enable the remote syslog server and point it at the manager on UDP/514. Devices send their own logs directly — the traffic does not pass through the controller — so the manager must accept syslog from the whole device subnet, not just the controller address. A UniFi OS console has its own remote-syslog setting under **OS Settings → Advanced**.

On the manager, accept syslog from the devices with a `<remote>` block in `ossec.conf`, and optionally set `<logall>yes</logall>` while validating. Real lines to copy into new decoders then land in `/var/ossec/logs/archives/archives.log`, already in the form remoted hands to analysisd.

Install:

```
sudo cp decoders/0100-unifi_device_decoders.xml /var/ossec/etc/decoders/unifi_device_decoders.xml
sudo cp decoders/0101-unifi_os_decoders.xml     /var/ossec/etc/decoders/unifi_os_decoders.xml
sudo cp rules/0100-unifi_device_rules.xml       /var/ossec/etc/rules/unifi_device_rules.xml
sudo cp rules/0101-unifi_os_rules.xml           /var/ossec/etc/rules/unifi_os_rules.xml
sudo rm -f /var/ossec/etc/decoders/symantec_decoders.xml
```

Do not copy `0330-symantec_decoders.xml`. Restart `wazuh-manager`. Confirm the device parent is the hijack, not a leftover standalone decoder:

```
sudo head -n 5 /var/ossec/etc/decoders/unifi_device_decoders.xml | cat
grep -n 'parent>symantec-av' /var/ossec/etc/decoders/unifi_device_decoders.xml
```

## Test

Offline, before touching the manager:

```
node scripts/simulate-decode.mjs --verbose
node scripts/simulate-decode.mjs --inventory   # daemons in the samples, and their volume
```

It replicates the parts of analysisd that decide whether a decoder fires — pre-decoding character by character, the `program_name` list split, the parent prematch, and the full child chain — and fails on:

- an escaping of `<` the Wazuh XML reader would reject (`&lt;` or CDATA)
- a sample whose pre-decoding yields a `program_name` after all, which would put it in the other decoder list where none of these decoders can see it
- two parents claiming the same line
- a regex that does not compile, or whose capture-group count differs from `<order>`
- an optional capture group with another capture after it
- a sample line that no decoder matches, or that misses the fields its family guarantees
- two decoders setting the same field to different values on one line, which means their patterns are not mutually exclusive
- a rule referencing a `$(field)` no decoder sets, a duplicate rule id, or an id outside its family's range
- a rule level above 16, which `rules_op.c` rejects at load time for the **whole** ruleset — `wazuh-logtest` then answers every line with `Failure to initializing session` and no alerts are produced at all, while naming only the offending level and not the rule
- a rule shadowed by a higher-level sibling

On the manager:

```
/var/ossec/bin/wazuh-logtest < samples/unifi-syslog.log
/var/ossec/bin/wazuh-logtest < samples/unifi-synthetic.log
```

`unifi-synthetic.log` is reconstructed rather than captured: it covers formats the decoders handle but that the capture never produced — console SSH and `sudo` activity, firewall drops, switch management sessions — so a regression there is caught locally instead of in production. Replace a line with a real one as soon as the environment yields it.

The sample lines deliberately omit the priority, because that is how remoted hands events to analysisd. Feeding a line **with** the priority makes pre-decoding fail on the shifted date offsets, and Phase 1 then shows only `full event` — a false negative that does not happen in production.

A successful run shows **no** `program_name` in Phase 1 — that is correct here, not a failure — then `decoder.name: unifi-device` or `unifi-os` in Phase 2, with `unifi.mac`, `unifi.model`, `unifi.firmware`, `unifi.daemon` and `unifi.message` on every line, plus `id` and event-specific fields on the recognised ones.

If `wazuh-logtest` reports `Invalid root element "decoder". Only "group" is allowed`, a decoder file was placed in `/var/ossec/etc/rules/`. Check that the files landed in the directories listed above.

If Phase 2 still says `symantec-av` with **no fields** and rule **7300**, the manager is still running a standalone `unifi-device` parent, or `/var/ossec/etc/decoders/symantec_decoders.xml` has replaced the stock prematch. The first decoder in `unifi_device_decoders.xml` must contain `<parent>symantec-av</parent>` and `<use_own_name>true</use_own_name>`. Delete the leftover Symantec file, restart `wazuh-manager`, and test again. wazuh-logtest does not reread XML by itself.

## What is decoded today

Every event exposes its device (`unifi.mac`, `unifi.model`, `unifi.firmware`), the daemon that produced it (`unifi.daemon`) and its message body (`unifi.message`). Events with a specific decoder also set `id`, the literal event marker taken from the message text, which is what the rules match on.

### Wireless — access points

- **Association lifecycle** — `associated`, `disassociated`, `deauthenticated` with reason, `AP-STA-CONNECTED`, `AP-STA-DISCONNECTED`, WPA `authorized`
- **Authentication failures** — possible PSK mismatch, 4-way and group-key handshake failure, EAPOL-Key with an invalid MIC, Michael MIC failure, MAC access-list refusal, 802.1X failure
- **RADIUS** — accounting session start, no response from the authentication server
- **Station tracking (`stahtd`)** — the JSON `STA_ASSOC_TRACKER` payload: event type, client MAC, VAP, association status, and the authentication algorithm and RSSI on association
- **Client events (`wevent`)** — `EVENT_STA_JOIN`, `EVENT_STA_LEAVE`, and `EVENT_STA_IP`, which binds a client MAC to an address and so makes later alerts on that address attributable
- **Driver (`kernel`)** — authentication-frame receipt with algorithm and RSSI, station association, and the `STA_TRACKER` DNS-timeout counter
- **Roaming** — the Ubiquiti `UBNT_ROAM` exchange, decoded so it can be silenced deliberately rather than by accident

### Switches

- **Ports** — link up, link down, SFP inserted, SFP removed, with port in stack notation
- **Spanning tree** — `DOT1S` port role transitions
- **Management** — `TRAPMGR` session start and end with user and source address
- **Platform** — fan speed and RPM

### UniFi OS consoles

- **Firewall** — the netfilter LOG line: rule identity as chain, action and index, the rule name from `DESCR`, interfaces, source and destination MAC and ethertype, addresses, protocol, ports, TTL, IP id, and the UID/GID present on locally generated traffic
- **SSH** — accepted and failed authentication with method, invalid user, pre-authentication disconnect, authentication attempts exhausted
- **sudo** — command execution with invoking and target user, and password failure
- **Probes (`mcad`)** — decoded only so they can be kept at level 0

Correlation rules: 5 PSK mismatches / 120 s per client MAC, 2 Michael MIC failures / 60 s, 5 RADIUS timeouts / 60 s, 20 associations / 60 s per client, 8 link-down events / 120 s per port, 15 firewall drops / 60 s per source IP, 8 SSH failures / 120 s per source IP, and 5 invalid-user attempts / 120 s per source IP.

### Sibling rules are ordered by level, not by file position

`_OS_AddRule` inserts each rule before the first sibling with a **lower** level, so the children of `100100` are evaluated in descending level order and file position only breaks ties. A generic rule with a high level therefore shadows every specific rule below it in level, wherever it sits in the file.

This bit immediately. The catch-all `100190` was first written at level 2 — reasonable-looking, below every alerting rule — and the simulation reported it shadowing `100160` and `100161`, the level-0 rules whose whole purpose is to silence the roaming and fan-speed chatter. An unconditional rule shadows every sibling below its own level, so a catch-all has to sit at level 0 and last in the file, where it ties with the silencing rules and loses the tie on position. The severity escalation lives in `100191` and `100192`, **children** of `100190`: a child is only evaluated after its parent matched, so it cannot outrank a specific sibling. `109390` in the console file is the same construction.

The simulation models this ordering, evaluating each rule's `<id>`, `<field>` and `<match>` conditions against the lines that were actually decoded rather than against a list of event names, and fails if any rule is shadowed. `--verbose` prints the winning rule per event.

## Scope

**EdgeSwitch is not covered here**, despite being Ubiquiti hardware. Its firmware is FASTPATH-derived and the format is unrelated:

```
<13> Aug 16 21:10:21 sw1 TRAPMGR[trapTask]: traputil.c(735) 248 %% Session 0 of type 3 started for user ubnt connected from 192.168.168.4.
```

A UniFi switch wraps its log as `switch: TRAPMGR: <message>`; EdgeSwitch emits a `file.c(line) counter %%` prefix instead. Worse, the bracket holds a **task name**, not a pid, and Wazuh accepts `p_name[pid]:` only when the character after `[` is a digit — so `TRAPMGR[trapTask]` pre-decodes to `program_name = NULL` while older firmware emitting `TRAPMGR[62222028]` pre-decodes to `program_name = TRAPMGR`. **The two firmware generations land in different decoder lists**, which means EdgeSwitch needs its own file with decoders in both. Some builds also emit RFC 5424, a hostname containing spaces, or a space after the priority, each of which shifts pre-decoding differently again. None of that should be written without a capture from the specific firmware in use.

Also out of scope, each needing its own file: the UniFi **CEF** integration (Settings → Control Plane → Integrations → Activity Logging), which is a structured format and the better source for IDS/IPS and administrator activity; EdgeRouter/EdgeOS; and UniFi Protect.

## Next samples

Seven patterns are built from `hostapd` behaviour rather than from captured traffic, and nothing in `samples/` exercises them — `simulate-decode.mjs` lists them as `no sample exercises` on every run:

- `AP-STA-POSSIBLE-PSK-MISMATCH`
- the 4-way and group-key handshake failures, and the EAPOL-Key timeout
- EAPOL-Key with an invalid MIC
- Michael MIC failure
- the MAC access-list refusal
- 802.1X authentication failure
- RADIUS no-response

Their literals must be confirmed against `hostapd` source — `src/ap/wpa_auth.c`, `src/ap/ieee802_11.c`, `src/ap/sta_info.c` and `src/radius/radius_client.c` — before they are trusted, because a pattern anchored on message text that does not exist fails silently and is indistinguishable from an event that never happened. The MAC access-list pattern is the weakest of the seven and should be treated as unverified.

The capture also covers only a quiet two minutes: it contains no failed authentication of any kind, no firewall drop, no configuration change, no DHCP and no PoE event. Enable `<logall>yes</logall>`, provoke each case once, and replace the corresponding synthetic line with the real one. If a line lands on the catch-all instead of its own decoder, `--inventory` names the daemon.

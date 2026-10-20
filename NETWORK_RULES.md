> Source: copied from internal case `goose_20261020` (`detection/NETWORK_RULES.md`, compiled 2026-10-20); credential defaults redacted to `<withheld>`.

# NETWORK_RULES — GOOSE 20261020 (US trucking/freight EtherHiding campaign)

**Case:** `goose_20261020` · Compiled 2026-10-20 · Detection/report lane (rev 2, after `samples/PAYLOAD_TEARDOWN.md`)
**Scope:** network and host detections for the freight-lure → VBS → PowerShell → Node agent chain, including the full discovery stack and the relay protocol.
**Evidence basis:** `samples/PAYLOAD_TEARDOWN.md` (loader source-equivalent, statically decoded — never executed), `chain/DEAD_DROP.md` (18-write contract history), `infra/INFRA_MAP.md`, `infra/TIMELINE.md`, `panel/PANEL_ID.md`, `etherhide/CLUSTER.md`, `samples/INDICATOR_TRIAGE.md`. No IOC host contacted; nothing executed; nothing submitted.
**Credential handling:** the loader hardcodes an AES-128-ECB key (a personal-name-shaped string) used for DNS/gist/cache payload decryption. It is a credential and a doxxing-adjacent artifact: it is **withheld from this document and from every rule**. Its location in the source is the decryption constant next to the DNS/gist decode paths — nothing more is recorded. No developer identity is named or inferred from it or from the Armenian code comments; both are code artifacts, not attribution.

Domains rotate (three generations in four months). Durable detections are the **techniques** (discovery stack, dead-drop read, role-word worker fetch, wscript→powershell chain, relay protocol) and the **panel routes/bundle names**, not any single hostname.

---

## 1. Host inventory with status

### 1.1 The 7-URL dead-drop set (current value of `0xCc4B…E61b`, chain-verified 2026-10-20)

Source: `chain/DEAD_DROP.md` §5 (write #18, 2026-10-12T11:31:16Z; eth_call byte-identical on two RPCs).

| Host | Role | Status |
|---|---|---|
| `api.xyz-code.biz` | panel/C2 | **LIVE** (panel 200 10-05) |
| `app.app-river.icu` | panel/C2 | **LIVE** (panel 200 10-03/10-05) |
| `play.app-open.click` | panel/C2 | **LISTED, likely nonfunctional** — registrar `serverHold` since 09-16, no cert since 08-25 (on-chain spine: present in 15/18 writes since 2026-05-16) |
| `check.okx3.io` | panel/C2 | **LIVE** (panel 200 10-05) |
| `tool.nffnj.workers.dev` | panel/C2 (CF Worker) | **LIVE** (panel 200 10-14) |
| `files.nffnj.workers.dev` | panel/C2 (CF Worker) | **LIVE per config** (zero direct scans) |
| `remember.nffnj.workers.dev` | panel/C2 (CF Worker) | **LIVE** (panel 200 10-14) |

**Version caveat (material):** this list is what the **June builds (main.js v1/v2)** consume. The **current build (v3/v4, 2026-09-03)** hardcodes `0xfb9B…D277`, whose `get()` returns an empty string — its blockchain layer yields nothing and it falls back to DNS/gist/cache (`samples/PAYLOAD_TEARDOWN.md` §9). The 7 URLs are live C2 for older agents and panel infrastructure; they are not what the published September build reads today.

### 1.2 The 6 September hosts (the 2026-09-04 report)

| Host | Role | Status |
|---|---|---|
| `carrierpackready.com` | stage-0 masquerade / lure domain | **QUIET** — registered 09-02, last cert 09-24 |
| `do.opinionvip.club` | panel/C2 (on-chain 2026-05-16 → dropped 2026-09-30) | **DROPPED, WARM** — two certs 10-14; `/static/main.js` 200 via OTX 10-11 |
| `amc-us.mprevive.com` | panel/C2 + payload host (on-chain 2026-05-16 → dropped 2026-09-21) | **DROPPED, WARM** — two certs 10-18; `/cdn/hello.txt` sighting 10-19 (CF "Suspected Phishing" page) |
| `play.app-open.click` | panel/C2 | overlaps the current set |
| `api-wls.ngrok.app` | C2 tunnel + installer download host | **RETIRED** — on-chain only 2026-08-31 → 2026-09-07 |
| `main-tunnel.ngrok.io` | C2 tunnel + installer download host | **RETIRED** — same window |

Stage-1 delivery host: `excite.aeafh.workers.dev` (the `IEX(IRM …)` target). Historical on-chain hosts from the 18-write rotation (May–Oct) — `play.trynode.info`, `*.trycloudflare.com`, `play/go/node/free.foundation.forum`, `find.beta-into.space`, `api.vooi-app.xyz`, `cfd.fins.workers.dev`, `tool./remove.ncsgo.workers.dev`, `cdn./node-worker.denisfsr-kemp.workers.dev`, `worker.defenders.workers.dev`, and a long tail of ngrok-free tunnels — are in `report/IOCS.json` (`historical_onchain_hosts`) and are retro-hunt gold: they were live C2 at some point in the rotation.

---

## 2. Network detections

### N1 — Dead-drop technique: JSON-RPC `eth_call` to a public RPC from an endpoint that should never speak JSON-RPC

**The loader's actual RPC set** (`samples/PAYLOAD_TEARDOWN.md` §4.3; v3/v4 query all three chains with the same contract):

- **BSC:** `bsc-dataseed2.bnbchain.org`, `bsc-dataseed.bnbchain.org`, `bsc.blockrazor.xyz`, `bsc.therpc.io`, `bsc-dataseed.nariox.org`, `bsc-dataseed.defibit.io`, `bsc-dataseed.ninicoin.io`, `bsc.nodereal.io`, `bsc-dataseed-public.bnbchain.org`, `bnb.rpc.subquery.network/public`
- **Polygon:** `polygon-rpc.com`, `polygon-bor-rpc.publicnode.com`, `rpc.ankr.com/polygon`, `polygon-bor.publicnode.com`
- **Arbitrum:** `arb1.arbitrum.io/rpc`, `arbitrum-one.publicnode.com`, `rpc.ankr.com/arbitrum`

**Contracts/selectors.** v1/v2 call `0xCc4BCd51e0eA7E254b0F30044538F6Cb86a4E61b`; v3/v4 call `0xfb9B234CdcE6dd9E0Eb4895b5682eBebE0b3D277`. The selector is computed at runtime as `keccak256('get()')` = `0x6d4ce63c`. Also relevant: `0x5e280f11` (`endpoint()`, same value — `chain/DEAD_DROP.md` §2) and `0x4ed3885e` (`set(string)` — the writer, which is **open to any address**, no owner check on-chain).

**Detection.** Alert on HTTPS POST with a JSON-RPC body containing `"eth_call"` and one of the two contract addresses or the `get()` selector, scoped to endpoint classes that have no business speaking `eth_call`: servers, dispatch/POS/scanner workstations, freight/TMS hosts, and any host where the call originates from `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `node.exe` or a headless browser spawned by a script host — not from a wallet process/extension. Hostname-only matching (SNI) is acceptable only under that scoping.

**False-positive reality.** Public RPCs serve every wallet, dApp and price widget on the planet. Crypto users and wallet apps legitimately `eth_call` all day. Scope is the entire rule.

**IR note.** This case's chain lane queried `bsc-dataseed.binance.org` / `bsc-rpc.publicnode.com` on 2026-10-20, and the loader-family reads will fire this rule from any analyst workstation doing the same. Expected validation hit.

**History-hunting.** The same rule against proxy logs back to **2026-05-12** (first contract write) finds past infections even where the domains are gone.

### N2 — DNS discovery: DoH TXT lookup of `_relay._discovery.foundation.forum`

Current builds resolve relays via DNS before falling back to the chain (`samples/PAYLOAD_TEARDOWN.md` §4.4):

- TXT name: **`_relay._discovery.foundation.forum`** (the discovery domain defaults to `foundation.forum`, overridable via `DNS_DISCOVERY_DOMAIN`).
- Transport: DoH GET to `https://cloudflare-dns.com/dns-query` and `https://dns.google/resolve` (`?name=…&type=TXT`) — the agent deliberately uses DoH so the lookup never touches the local resolver.
- Payload shape: hex text in the TXT record (AES-128-ECB encrypted JSON `{urls, ts}`; the key is withheld — see the header).

**Detection.** Alert on DoH queries for `_relay._discovery.` names or TXT lookups under `foundation.forum` from script hosts / Node processes. This is highly specific — a legitimate service does not publish relay lists in DNS TXT under `_relay._discovery.`. Note that `foundation.forum` also served panel/C2 subdomains (`play./go./node./free.foundation.forum`, on-chain May 2026) and `am.foundation.forum` served the panel kit in October — the domain is a campaign anchor across layers, not a single-purpose host. **Do not resolve it yourself as a check** — it is C2 infrastructure; passive/DNS-log detection only.

Also alert on the sibling fallback: HTTPS GET to `https://gist.githubusercontent.com/wservices66-maker/53ba3186cf8ec0cada46fc1ccb4a0ec71/raw/apiKey` (currently 404; hex+AES payload shape as the TXT record).

### N3 — Stage-1 delivery shape: role-word `*.workers.dev` fetched by a script host

HTTP(S) GET to a `*.workers.dev` hostname whose first label is a generic role word — `tool.`, `files.`, `remember.`, `excite.`, `api.`, `cdn.`, `remove.`, `crs.`, `cds.`, `down.` — **from a script host** (`powershell.exe`, `wscript.exe`, `cscript.exe`, `curl`/`wget` launched by a script host), or shortly after a `.vbs`/`.js`/`.ps1` execution:

```
^(tool|files|remember|excite|api|cdn|remove|down|crs|cds)\.[a-z0-9-]+\.workers\.dev$
```

Known instances: `excite.aeafh.workers.dev` (stage-1), `tool./files./remember.nffnj.workers.dev` (current config), `cdn./node-worker.denisfsr-kemp.workers.dev`, `cds.aiservices.workers.dev`, `remove./tool.ncsgo.workers.dev`, `worker.defenders.workers.dev`, `cfd./down.fins.workers.dev`. The **namespace** rotates; the role-word shape persists across all generations (and across the on-chain rotation history, which contains `node-worker.`/`cdn.`/`worker.` entries from May onward).

**False positives.** Legitimate Workers use role-word subdomains too; the discriminator is the client (browser/CI vs script host). Do not alert on the shape alone from browsing traffic.

### N4 — Relay protocol signatures (the panel's back end)

The agent talks to the panel backend over two transports (`samples/PAYLOAD_TEARDOWN.md` §5):

- **WSS:** WebSocket at path **`/ws`** (appended to the relay URL), JSON in each message.
- **TCP:** frames are a **4-byte big-endian length prefix followed by a UTF-8 JSON body** (oversized frames rejected).
- **Relay discovery probe:** request to `<backend>/discovery/relay` expecting JSON `{wsUrl, tcpAddr}` (optionally `udpAddr`, peer lists).
- **Register packet JSON keys** (excellent network signatures, present verbatim in the wire format):
  `type: "register"`, `machine_uuid`, `hostname`, `username`, `runAs`, `isElevated`, `platform`, `arch`, `connection_platform`, `connected_transport`, `connected_endpoint`, `public_ip`, `super_admin_key`, `comment`.
- **Server replies:** `{"type":"registered","client_id":…}` and `{"type":"relay-peers","peers":[…]}`.
- **Message-type vocabulary** (handler table): `command-result`, `data-collect`, `data-status`, `exe-received`, `file-*`, `get-data`, `hdesktop-launch`, `install-*`, `proc-*`, `software-*`, `start-terminal`, `stop-terminal`, `terminal-*`, `start-vnc`, `stop-vnc`, `vnc-*`, `register`, `registered`, `relay-peers`, `ping`.

**Detection sketches (TLS inspection or endpoint egress):**

```
alert http any any -> $EXTERNAL_NET any (
  msg:"GOOSE20261020 NodeRemote relay discovery probe";
  http.uri; content:"/discovery/relay";
  http.response_body; content:"\"wsUrl\""; content:"\"tcpAddr\"";
  sid:2026102011; rev:1;)

alert tcp any any -> $EXTERNAL_NET any (
  msg:"GOOSE20261020 NodeRemote register packet (TCP framing)";
  flow:established,to_server;
  content:"|00 00|"; depth:2; content:"\"machine_uuid\""; content:"\"super_admin_key\"";
  sid:2026102012; rev:1;)
```

For WSS, match the register JSON keys in decrypted WebSocket payloads (or on the endpoint via EDR/network agent): `machine_uuid` + `super_admin_key` + `connected_transport` appearing together is this family — the keys survive the obfuscation in the raw bundles too (hex-escaped form; see YARA rule `GOOSE_20261020_NodeRemote_Protocol_Register`). `public_ip` is populated via `api.ipify.org` — an agent-side fetch to ipify immediately before a register packet is a useful correlator.

### N5 — Panel routes and page signature (proxy/TLS-inspection)

Domains rotate; **routes and bundle names persist across hosts** (`panel/PANEL_ID.md` §3.4):

- `/static/main.js` — the **agent download path** in the installer (four ngrok hosts + the GitHub raw URL) AND a 200-observed panel route; combine with cluster SNI or page title.
- `/internal/clients/telemeter` (401/403) and `/delivery/relays` (403) — **panel backend routes only**; neither string appears in agent code v1–v4 (`PAYLOAD_TEARDOWN.md` §11.1). `/delivery/relays` was observed 2026-06-16 (OTX), earlier than the public footprint — flagged as an unresolved date discrepancy.
- `/cdn/hello.txt` — **NOT a platform or health-check signature**; 11/11 urlscan observations on `amc-us.mprevive.com`, all Cloudflare 403 block pages. One member of the cluster signature only.
- `/cdn/hello_world.txt` — the commented non-admin PowerShell fallback path in the installer (`api-truck.ngrok.app`).
- Bundle/chunk names (build-specific, durable in proxy logs today): `vendor-CUghsita.js`, `vendor-ybeVSQkp.css`, `editor-stack-77ujE2Vu.js`, `terminal-stack-BAtsiuwF.js`, `terminal-stack-6GBZ9nXN.css`, `windowing-stack-BpHlmP-1.js`, `markdown-stack-CGN4Zb3k.js`; entry bundle rolled `index-BYo0etwW.js` → `index-F4qs5gg3.js` between 2026-10-05 and 2026-10-13/14.
- Page signature (TLS-inspected HTML): title `Remote Support Console`, ~3.15–3.18 MB, Google Fonts **Sora** + **Manrope**, fetch to `https://www.cloudflare.com/cdn-cgi/trace`, dark navy two-column login, `Key`/`Token` placeholders `system-key`/`system-token`, `Enter Desktop` button.

**Title warning.** Two unrelated apps share the page title (`localupdateai.com/panel/` ConnectAI; `operator.digitax.web.id` Indonesian token login). Define the cluster by title **plus** bundle hashes **plus** page size **plus** routes.

---

## 3. Host detections

### H1 — Sysmon: VBScript launching hidden PowerShell with `IEX(IRM …)` (stage 1)

Sysmon Event ID 1: `ParentImage` `\wscript.exe`/`\cscript.exe` → `Image` `\powershell.exe`, `CommandLine` contains `-ExecutionPolicy Bypass` **and** `IEX` **and** `IRM`. Bonus anchors: `-WindowStyle Hidden`, freight-themed `.vbs` names (`CARRIER_ONB`, `FREIGHT`, `PACKET_UPDATE`). Corroborate with PowerShell Script Block Logging (4104): `IEX(IRM` + a `workers.dev`/`ngrok` URL. Enable 4104 on freight/dispatch workstations.

### H2 — Host artifacts of the installed agent (NodeRemote / relay RAT)

From the installer teardown (`samples/PAYLOAD_TEARDOWN.md` §2, §7):

- Install dir: **`%LOCALAPPDATA%\WebServer-<COMPUTERNAME>\`** (legacy name: `%LOCALAPPDATA%\NodeRemoteSupport\`).
- Files: `main.js`, `nodeupdate.vbs` (hidden WScript launcher), `node\node.exe` — **Node.js v20.11.0** downloaded per-arch from `nodejs.org/download/release/v20.11.0/`, `.env` containing `SUPER_ADMIN_KEY=` (default value `<withheld>` — a personal-name-shaped credential default).
- Scheduled task: **`NodeRemote{GUID}`** where GUID = first 16 bytes of `SHA256(username)` (deterministic per user); description **"My Custom Important Task"**; action `wscript.exe //nologo "<…>\nodeupdate.vbs"`; trigger **logon + repeat `PT1H`**; `RunLevel=1` (highest) when installed as admin; registered create-or-update then started immediately; any `*NodeRemote*` task is force-started at the end.
- Agent telemetry: node.exe outbound to DoH endpoints, public RPCs (N1/N2), `api.ipify.org` fetch, WSS `/ws` or TCP framed-JSON to relay hosts.

Sigma sketch (task creation, TaskScheduler Operational 106 / EDR):

```yaml
detection:
  selection: {TaskName|contains: 'NodeRemote'}
  condition: selection
```

### H3 — The VNC/terminal capability (for scoping severity)

The agent is a full hands-on-keyboard RAT: VNC (PowerShell + embedded C# `VncWorker`, `SendInput`/`BitBlt`), node-pty terminal, file manager, process manager, clipboard (via `clipboardy`), software inventory, data collection, remote installer. Detection add-ons: `Add-Type` compilation of a `VncWorker`-class script, `node-pty` module loads in node.exe, and the frame-control strings `__CAPTURE_TILES__` / `__READY__` on the worker's stdio (host-side). A confirmed `NodeRemote` install on a freight host should be treated as hands-on-keyboard compromise.

---

## 4. Why blocking `*.workers.dev` wholesale is unacceptable — and what to do instead

`workers.dev` is Cloudflare's shared serverless platform hosting thousands of legitimate developer projects, internal tools and demos. A global block breaks real work, breeds an unvettable exception culture, and **does not stop this actor**: the campaign already ran ngrok tunnels (May–Sept), aged custom domains and Cloudflare Workers (Sept–Oct), DNS TXT discovery, gist fallback and a multi-chain dead drop. Block one platform and the next rotation lands elsewhere while your helpdesk burns.

Instead:

1. **Alert on shape** (role-word subdomain + script-host client — N3), not on the suffix.
2. **Block narrowly**: the known namespaces today (`*.aeafh.workers.dev`, `*.nffnj.workers.dev`, `*.ncsgo.workers.dev`, `*.fins.workers.dev`), accepting rotation.
3. **Constrain egress**: freight/dispatch workstations and servers should never fetch `workers.dev` or `ngrok.*` — allow-listing beats a global deny.
4. **Report to the platform**: Workers have no origin IP to sinkhole; disruption requires Cloudflare abuse action. Registrar/Cloudflare filings are an operator decision (`report/HANDLING.md`).
5. **Hunt retroactively**: DNS/proxy logs back to 2026-05-12 searched with the role-word regex, N1 rule, N2 DoH name, the relay protocol keys and the panel routes are where past compromise is found. The on-chain rotation table (`report/IOCS.json`) gives the exact host/date windows.

---

## 5. Validation performed

- `yarac detection/GOOSE_20261020.yar` — clean (exit 0), **11 rules**.
- Negative corpus: `yara -r` over `/usr/bin` and `/usr/lib` (`/usr/share/php` absent) — **0 matches** (5 setuid binaries unreadable in the first pass: `mount.nfs`, `mount.nfs4`, `umount.nfs`, `dbus-daemon-launch-helper`, `ssh-keysign`).
- Positive sanity: raw `main_v1.js`/`main_v4.js` hit `NodeRemote_Agent_ConfigTriple` + `NodeRemote_Protocol_Register`; `info.txt` hits `NodeRemote_Installer`; the screenshot-derived rules fire on their source artifacts.
- No host contacted (the DNS TXT record was deliberately **not** queried — it is C2). No sample executed. Nothing submitted.

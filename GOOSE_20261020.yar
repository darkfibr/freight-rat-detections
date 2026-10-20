/*
 * GOOSE_20261020 — YARA pack for the US trucking/freight EtherHiding campaign
 * Case: goose_20261020 (2026-10-20)
 *
 * Build constraint (applies to EVERY rule below, restated in each rule's meta):
 * the stage-1 VBS and stage-2 JS samples were NOT obtained (see
 * samples/ACQUISITION.md). Every string here is taken from published artifacts
 * (the @vxunderground 2026-09-04 thread screenshots, transcribed twice), from
 * public urlscan/OTX observations of the panel (panel/PANEL_ID.md), or from
 * read-only BSC chain reads (chain/evidence/, samples/INDICATOR_TRIAGE.md §2).
 * Nothing was executed, and no IOC host was contacted.
 *
 * Design rule: no rule matches a generic construct alone (no bare "IEX", no
 * bare "WScript.Shell", no bare "eval"). Every rule is anchored on a
 * combination of campaign-specific tokens.
 *
 * Sources for the panel rules: panel/PANEL_ID.md (verdict table, §3.2 chunk
 * list, §3.4 routes). Beware the two documented title false positives
 * (localupdateai.com "ConnectAI", operator.digitax.web.id): the title alone is
 * never a rule; it is always combined with the login triple or badge copy.
 */

rule GOOSE_20261020_Lure_VBS_FreightPacket
{
    meta:
        description = "Freight-lure two-line VBS loader: WScript.Shell launching hidden PowerShell with IEX(IRM https://*.workers.dev), incl. the ONLINE FREIGHT SERVICES_CARRIER_ONB_PACKET_UPDATE (1).vbs lure filename"
        reference = "goose_20261020: samples/INDICATOR_TRIAGE.md s4 (screenshot transcription x2), samples/ACQUISITION.md (source post x.com/vxunderground/status/2095951516805054469)"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts and chain reads only."
    strings:
        $fn  = "ONLINE FREIGHT SERVICES_CARRIER_ONB_PACKET_UPDATE" nocase ascii wide
        $wsh = "WScript.Shell" nocase ascii wide
        $iex = "IEX(IRM https://" nocase ascii wide
        $wk  = ".workers.dev" nocase ascii wide
    condition:
        // filename + the download-exec shape, or the full two-line shape without filename
        ($fn and $iex and $wk) or ($wsh and $iex and $wk)
}

rule GOOSE_20261020_PS_IEX_IRM_WorkersOrNgrok
{
    meta:
        description = "PowerShell stage: IEX(IRM ...) download-execute fetching from a *.workers.dev or *.ngrok.* URL on the same command line"
        reference = "goose_20261020: samples/INDICATOR_TRIAGE.md s3-s4 (stage chain), infra/INFRA_MAP.md (ngrok + workers.dev hosting classes)"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts and chain reads only."
    strings:
        // one regex = the combination itself; cannot fire on bare IEX or a bare platform string
        $stage = /IEX\s*\(\s*IRM[^\r\n]{0,200}(workers\.dev|ngrok)/ nocase ascii wide
    condition:
        $stage
}

rule GOOSE_20261020_Panel_RemoteSupportConsole_Login
{
    meta:
        description = "Bespoke 'Remote Support Console' operator panel login: title + 'Enter Desktop' button + system-key/system-token field placeholders (unbranded kit, NOT a named commercial RMM)"
        reference = "goose_20261020: panel/PANEL_ID.md s1.1, s5 (verdict 0.95 shared kit / 0.90 not a named RMM); case report report/CASE_GOOSE_20261020.md"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts and chain reads only. Triple anchor avoids the two known unrelated apps that share the page title alone (panel/PANEL_ID.md s3.3)."
    strings:
        $title = "REMOTE SUPPORT CONSOLE" nocase ascii wide
        $btn   = "Enter Desktop" nocase ascii wide
        $key   = "system-key" nocase ascii wide
        $tok   = "system-token" nocase ascii wide
    condition:
        $title and $btn and any of ($key, $tok)
}

rule GOOSE_20261020_Panel_ThreeBadge_Copy
{
    meta:
        description = "Distinctive three-badge marketing copy of the bespoke panel login: LIVE CLIENT STREAM / ROLE-AWARE MANAGEMENT / REALTIME AUDIT VISIBILITY"
        reference = "goose_20261020: panel/PANEL_ID.md s1.1 (verbatim page text), s2 (exact-phrase searches: zero product copy)"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts and chain reads only."
    strings:
        $b1 = "LIVE CLIENT STREAM" nocase ascii wide
        $b2 = "ROLE-AWARE MANAGEMENT" nocase ascii wide
        $b3 = "REALTIME AUDIT VISIBILITY" nocase ascii wide
    condition:
        all of them
}

rule GOOSE_20261020_Panel_Vite_Chunk_Build
{
    meta:
        description = "Byte-identical Vite content-hashed asset chunks of the panel codebase, identical across five unrelated hosts (build-specific but durable enough to hunt in proxy/CDN logs)"
        reference = "goose_20261020: panel/PANEL_ID.md s3.2 (seven identical chunks across remember.nffnj.workers.dev, am.foundation.forum, check.okx3.io, api.xyz-code.biz, amc-us.mprevive.com)"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts (urlscan asset lists) and chain reads only. Chunks are content-hashed: they change on rebuild (entry bundle index-BYo0etwW.js -> index-F4qs5gg3.js between 2026-10-05 and 2026-10-13/14)."
    strings:
        $c1 = "vendor-CUghsita.js"
        $c2 = "vendor-ybeVSQkp.css"
        $c3 = "editor-stack-77ujE2Vu.js"
        $c4 = "terminal-stack-BAtsiuwF.js"
        $c5 = "terminal-stack-6GBZ9nXN.css"
        $c6 = "windowing-stack-BpHlmP-1.js"
        $c7 = "markdown-stack-CGN4Zb3k.js"
    condition:
        // the named triple (c1/c3/c4) satisfies this; threshold 3 of 7 widens to the observed set
        3 of ($c*)
}

rule GOOSE_20261020_EtherHiding_BSC_Contract_Addresses
{
    meta:
        description = "EtherHiding dead-drop BSC contract addresses as hex strings: 0xCc4B...E61b (live, returns the C2 URL list) and 0xfb9B...D277 (byte-identical code, empty state)"
        reference = "goose_20261020: samples/INDICATOR_TRIAGE.md s2 (eth_call/eth_getCode, two RPCs, byte-identical), chain/evidence/"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts and chain reads only."
    strings:
        $addr1 = "0xCc4BCd51e0eA7E254b0F30044538F6Cb86a4E61b" nocase ascii wide
        $addr2 = "0xfb9B234CdcE6dd9E0Eb4895b5682eBebE0b3D277" nocase ascii wide
    condition:
        any of them
}

/*
 * Ground-truth rules (added after samples/PAYLOAD_TEARDOWN.md recovered the
 * loader source-equivalent from the operator's own public GitHub repo
 * wservices66-maker/hello). The published 2026-09-04 bytes were still never
 * obtained and the repo builds' hashes differ from the published hashes - these
 * rules match the recovered v1-v4 bundles (verified below) and the decoded/
 * implant-side artifacts. The hardcoded AES-128-ECB key is deliberately NOT a
 * string in any rule; it is a credential and stays out of detection content.
 */

rule GOOSE_20261020_NodeRemote_Agent_ConfigTriple
{
    meta:
        description = "NodeRemote/relay RAT agent family: the frozen .env config triple RELAY_URL + BLOCKCHAIN_CONTRACT + SUPER_ADMIN_KEY (process.env reads survive obfuscation in main.js v1-v4)"
        reference = "goose_20261020: samples/PAYLOAD_TEARDOWN.md s3-s4 (static deobfuscation of wservices66-maker/hello main.js v1-v4)"
        date = "2026-10-20"
        sample = "published bytes not obtained"
        note = "The 2026-09-04 published sample was not obtained; rule built from source-equivalent repo builds (wservices66-maker/hello), published artifacts and chain reads. Verified to match raw v1-v4 bundles."
    strings:
        $rel = "RELAY_URL"
        $blk = "BLOCKCHAIN_CONTRACT"
        $sup = "SUPER_ADMIN_KEY"
    condition:
        all of them
}

rule GOOSE_20261020_NodeRemote_Protocol_Register
{
    meta:
        description = "NodeRemote relay register packet keys (machine_uuid + super_admin_key + connected_transport) in plain or hex-escaped form - raw bundles carry the escaped form, decoded/implant copies carry plain"
        reference = "goose_20261020: samples/PAYLOAD_TEARDOWN.md s5.3 (register packet fields)"
        date = "2026-10-20"
        sample = "published bytes not obtained"
        note = "The 2026-09-04 published sample was not obtained; rule built from source-equivalent repo builds, published artifacts and chain reads. Verified to match raw v1-v4 bundles via the escaped form."
    strings:
        $ma_plain = "machine_uuid"
        $ma_esc   = "\\x6d\\x61\\x63\\x68\\x69\\x6e\\x65\\x5f\\x75\\x75\\x69\\x64" nocase
        $su_plain = "super_admin_key"
        $su_esc   = "\\x73\\x75\\x70\\x65\\x72\\x5f\\x61\\x64\\x6d\\x69\\x6e\\x5f\\x6b\\x65\\x79" nocase
        $ct_plain = "connected_transport"
        $ct_esc   = "\\x63\\x6f\\x6e\\x6e\\x65\\x63\\x74\\x65\\x64\\x5f\\x74\\x72\\x61\\x6e\\x73\\x70\\x6f\\x72\\x74" nocase
    condition:
        any of ($ma_*) and any of ($su_*) and any of ($ct_*)
}

rule GOOSE_20261020_NodeRemote_Installer
{
    meta:
        description = "NodeRemote PowerShell installer (info.txt): hidden VBS launcher + scheduled task NodeRemote{GUID} with the 'My Custom Important Task' description"
        reference = "goose_20261020: samples/PAYLOAD_TEARDOWN.md s2 (installer teardown, wservices66-maker/hello info.txt)"
        date = "2026-10-20"
        sample = "published bytes not obtained"
        note = "The 2026-09-04 published sample was not obtained; rule built from source-equivalent repo artifacts (info.txt), published artifacts and chain reads."
    strings:
        $i1 = "NodeRemote" ascii nocase
        $i2 = "nodeupdate.vbs" ascii nocase
        $i3 = "My Custom Important Task" ascii
        $i4 = "WebServer-" ascii
    condition:
        $i1 and $i2 and 1 of ($i3, $i4)
}

rule GOOSE_20261020_NodeRemote_Agent_DiscoveryStack
{
    meta:
        description = "NodeRemote agent discovery stack (decoded/implant-side): encrypted relay cache last_known_relays.json + DNS TXT anchor _relay._discovery.foundation.forum - raw v1-v4 bundles encode these strings (base64+RC4) so this rule targets decoded copies, dropped scripts and memory"
        reference = "goose_20261020: samples/PAYLOAD_TEARDOWN.md s4 (discovery layers)"
        date = "2026-10-20"
        sample = "published bytes not obtained"
        note = "The 2026-09-04 published sample was not obtained; rule built from source-equivalent repo builds (statically decoded, never executed), published artifacts and chain reads."
    strings:
        $d1 = "last_known_relays.json" ascii wide
        $d2 = "_relay._discovery." ascii wide
        $d3 = "foundation.forum" ascii wide
    condition:
        2 of ($d*)
}

rule GOOSE_20261020_C2_Host_Cluster_Threshold
{
    meta:
        description = "Campaign C2/host cluster: fires when 2+ known hosts appear in one file, so a single shared CDN string or one rotation member cannot trigger it"
        reference = "goose_20261020: samples/INDICATOR_TRIAGE.md s1 (7-URL chain read + Sept set), infra/INFRA_MAP.md, panel/PANEL_ID.md s3.1 (cluster hosts), report/IOCS.json (full machine-readable set)"
        date = "2026-10-20"
        sample = "not obtained"
        note = "Sample not obtained; rule built from published artifacts and chain reads only. Host set = current 7-URL dead-drop config (chain-verified 2026-10-20), the September reported set, and panel-cluster hosts (urlscan). Domains rotate; treat as a snapshot."
    strings:
        // current dead-drop config (chain-verified 2026-10-20)
        $h01 = /(^|[^a-z0-9.\-])api\.xyz-code\.biz/ nocase
        $h02 = /(^|[^a-z0-9.\-])app\.app-river\.icu/ nocase
        $h03 = /(^|[^a-z0-9.\-])play\.app-open\.click/ nocase
        $h04 = /(^|[^a-z0-9.\-])check\.okx3\.io/ nocase
        $h05 = /(^|[^a-z0-9.\-])tool\.nffnj\.workers\.dev/ nocase
        $h06 = /(^|[^a-z0-9.\-])files\.nffnj\.workers\.dev/ nocase
        $h07 = /(^|[^a-z0-9.\-])remember\.nffnj\.workers\.dev/ nocase
        // September reported set (2026-09-04 thread) + stage-1 host
        $h08 = /(^|[^a-z0-9.\-])carrierpackready\.com/ nocase
        $h09 = /(^|[^a-z0-9.\-])do\.opinionvip\.club/ nocase
        $h10 = /(^|[^a-z0-9.\-])amc-us\.mprevive\.com/ nocase
        $h11 = /(^|[^a-z0-9.\-])api-wls\.ngrok\.app/ nocase
        $h12 = /(^|[^a-z0-9.\-])main-tunnel\.ngrok\.io/ nocase
        $h13 = /(^|[^a-z0-9.\-])excite\.aeafh\.workers\.dev/ nocase
        // panel-cluster hosts (urlscan-cluster, 2026-09-21..2026-10-14)
        $h14 = /(^|[^a-z0-9.\-])lxservice\.net/ nocase
        $h15 = /(^|[^a-z0-9.\-])cfd\.fins\.workers\.dev/ nocase
        $h16 = /(^|[^a-z0-9.\-])tool\.ncsgo\.workers\.dev/ nocase
        $h17 = /(^|[^a-z0-9.\-])remember\.ncsgo\.workers\.dev/ nocase
        $h18 = /(^|[^a-z0-9.\-])api\.beta-into\.space/ nocase
        $h19 = /(^|[^a-z0-9.\-])foundation\.forum/ nocase
        $h20 = /(^|[^a-z0-9.\-])am\.foundation\.forum/ nocase
        $h21 = /(^|[^a-z0-9.\-])down\.fins\.workers\.dev/ nocase
        // apexes that themselves served the panel or the lure (left-boundary: does NOT fire inside a subdomain)
        $h22 = /(^|[^a-z0-9.\-])app-river\.icu/ nocase
        $h23 = /(^|[^a-z0-9.\-])okx3\.io/ nocase
        $h24 = /(^|[^a-z0-9.\-])xyz-code\.biz/ nocase
        $h25 = /(^|[^a-z0-9.\-])opinionvip\.club/ nocase
        $h26 = /(^|[^a-z0-9.\-])mprevive\.com/ nocase
    condition:
        2 of ($h*)
}

# APB scripts for "edge-1" (RouterOS v7)
# Generated 2026-09-03 17:45:29Z by APB.
#
# This file contains the API token for this router. Treat it as a password:
# do not commit it, do not share it, and remove the file from the router once
# the import has finished. If it leaks, revoke the token in the console and
# issue a new one.
#
# Import with:  /import file-name=<this file>
#
# The script bodies below are assembled one piece at a time into a variable and
# then installed. That is deliberately more verbose than the single quoted
# string RouterOS itself exports, and it is what makes this file safe to move
# between machines: there are no line continuations, so a file converted to
# CRLF on the way here still imports correctly.
#
:global apbSrc

# --- apb-sync: applies incremental blocklist changes
:set apbSrc ""
:set apbSrc ($apbSrc . "# APB incremental sync for edge-1.\r\n# Applies the changes the server has queued since the cursor held in RAM.\r\n")
:set apbSrc ($apbSrc . "# Entries are added with a timeout so RouterOS keeps them in memory and never\r\n# writes them to flash.\r\n:local Url \"https://apb.example.org/api/v1\"\r\n")
:set apbSrc ($apbSrc . ":local Token \"apb_SAMPLETOKENONLY000000\"\r\n:local List \"APB\"\r\n:local UA \"apb-router\"\r\n:local Timeout 520w\r\n:local MaxLoops 20\r\n:global apbCursor\r\n")
:set apbSrc ($apbSrc . ":global apbLock\r\n:local Hdr (\"Authorization: Bearer \" . \$Token . \",user-agent: \" . \$UA . \",X-Apb-Agent: \" . \$UA)\r\n")
:set apbSrc ($apbSrc . ":local Now [/system resource get uptime]\r\n:local Run true\r\n:if ([:typeof \$apbLock] = \"time\") do={ :if ((\$Now - \$apbLock) < 3m) do={ :set Run false } }\r\n")
:set apbSrc ($apbSrc . ":if (\$Run) do={\r\n:set apbLock \$Now\r\n:do {\r\n:if ([:typeof \$apbCursor] != \"num\") do={\r\n:log info \"APB: no cursor in memory, rebuilding the list\"\r\n")
:set apbSrc ($apbSrc . "/system script run apb-bootstrap\r\n} else={\r\n:local More true\r\n:local Loops 0\r\n:do {\r\n:set More false\r\n:set Loops (\$Loops + 1)\r\n")
:set apbSrc ($apbSrc . ":local Held [:len [/ip firewall address-list find list=\$List]]\r\n:local Res \"\"\r\n")
:set apbSrc ($apbSrc . ":do { :set Res [/tool fetch url=(\$Url . \"/sync\?c=\" . \$apbCursor . \"&n=\" . \$Held) http-method=get http-header-field=\$Hdr mode=https check-certificate=yes-without-")
:set apbSrc ($apbSrc . "crl output=user as-value] } on-error={ :log warning (\"APB: sync could not reach \" . \$Url . \" - run apb-test for detail\") }\r\n")
:set apbSrc ($apbSrc . ":if ([:typeof \$Res] = \"array\") do={\r\n:if ((\$Res->\"status\") = \"finished\") do={\r\n:local Next -1\r\n:local Resync false\r\n:local Added 0\r\n:local Removed 0\r\n")
:set apbSrc ($apbSrc . ":foreach Tok in=[:toarray (\$Res->\"data\")] do={\r\n:if ([:len \$Tok] > 1) do={\r\n:local K [:pick \$Tok 0 1]\r\n:local V [:pick \$Tok 1 [:len \$Tok]]\r\n")
:set apbSrc ($apbSrc . ":if (\$K = \"+\") do={ :if ([:len [/ip firewall address-list find list=\$List address=\$V]] = 0) do={ :do { /ip firewall address-list add list=\$List address=\$V timeout=")
:set apbSrc ($apbSrc . "\$Timeout comment=\"apb\" ; :set Added (\$Added + 1) } on-error={} } }\r\n")
:set apbSrc ($apbSrc . ":if (\$K = \"-\") do={ :do { /ip firewall address-list remove [find list=\$List address=\$V] ; :set Removed (\$Removed + 1) } on-error={} }\r\n")
:set apbSrc ($apbSrc . ":if (\$K = \"c\") do={ :set Next [:tonum \$V] }\r\n:if (\$K = \"m\") do={ :set More true }\r\n:if (\$K = \"r\") do={ :set Resync true }\r\n}\r\n}\r\n")
:set apbSrc ($apbSrc . ":if (\$Resync) do={\r\n:log info \"APB: cursor too old, falling back to a full rebuild\"\r\n:set More false\r\n/system script run apb-bootstrap\r\n} else={\r\n")
:set apbSrc ($apbSrc . ":if (\$Next >= 0) do={ :set apbCursor \$Next }\r\n")
:set apbSrc ($apbSrc . ":if ((\$Added + \$Removed) > 0) do={ :log info (\"APB: applied +\" . \$Added . \" -\" . \$Removed . \", cursor \" . \$apbCursor) }\r\n}\r\n}\r\n}\r\n")
:set apbSrc ($apbSrc . "} while=(\$More && (\$Loops < \$MaxLoops))\r\n}\r\n} on-error={ :log error \"APB: sync script aborted\" }\r\n:set apbLock\r\n}\r\n")
:do { /system script remove [find name="apb-sync"] } on-error={ :log debug "APB: no previous apb-sync" }
/system script add name="apb-sync" policy=read,write,test dont-require-permissions=no comment="APB: applies incremental blocklist changes" source=$apbSrc

# --- apb-bootstrap: rebuilds the whole list after a reboot
:set apbSrc ""
:set apbSrc ($apbSrc . "# APB full rebuild for edge-1.\r\n# The blocklist lives in RAM, so it is empty after a reboot. This script pulls\r\n")
:set apbSrc ($apbSrc . "# the whole list back in pages small enough for the fetch buffer and stores the\r\n# server cursor so the incremental sync can take over.\r\n")
:set apbSrc ($apbSrc . "# It also runs when the server reports that the cursor is too old to catch up.\r\n:local Url \"https://apb.example.org/api/v1\"\r\n")
:set apbSrc ($apbSrc . ":local Token \"apb_SAMPLETOKENONLY000000\"\r\n:local List \"APB\"\r\n:local UA \"apb-router\"\r\n:local Timeout 520w\r\n:local MaxPages 500\r\n:global apbCursor\r\n")
:set apbSrc ($apbSrc . ":global apbBootLock\r\n:local Hdr (\"Authorization: Bearer \" . \$Token . \",user-agent: \" . \$UA . \",X-Apb-Agent: \" . \$UA)\r\n")
:set apbSrc ($apbSrc . ":local Now [/system resource get uptime]\r\n:local Run true\r\n")
:set apbSrc ($apbSrc . ":if ([:typeof \$apbBootLock] = \"time\") do={ :if ((\$Now - \$apbBootLock) < 30m) do={ :set Run false } }\r\n:if (\$Run) do={\r\n:set apbBootLock \$Now\r\n:do {\r\n")
:set apbSrc ($apbSrc . ":local Next 0\r\n:local Page 0\r\n:local NewCursor -1\r\n:local Total 0\r\n:local Failed false\r\n:local Started false\r\n:do {\r\n:set Page (\$Page + 1)\r\n")
:set apbSrc ($apbSrc . ":local U (\$Url . \"/full\")\r\n:if (\$Next > 0) do={ :set U (\$U . \"\?a=\" . \$Next) }\r\n:set Next 0\r\n:local Res \"\"\r\n")
:set apbSrc ($apbSrc . ":do { :set Res [/tool fetch url=\$U http-method=get http-header-field=\$Hdr mode=https check-certificate=yes-without-crl output=user as-value] } on-error={ :set Failed tr")
:set apbSrc ($apbSrc . "ue ; :log warning (\"APB: rebuild could not reach \" . \$U . \" - check DNS, routing and the certificate setting\") }\r\n:if (!\$Failed) do={\r\n")
:set apbSrc ($apbSrc . ":if ([:typeof \$Res] = \"array\") do={\r\n:if ((\$Res->\"status\") = \"finished\") do={\r\n:if (!\$Started) do={\r\n:set Started true\r\n:set apbCursor\r\n")
:set apbSrc ($apbSrc . "/ip firewall address-list remove [find list=\$List]\r\n}\r\n:foreach Tok in=[:toarray (\$Res->\"data\")] do={\r\n:if ([:len \$Tok] > 1) do={\r\n")
:set apbSrc ($apbSrc . ":local K [:pick \$Tok 0 1]\r\n:local V [:pick \$Tok 1 [:len \$Tok]]\r\n")
:set apbSrc ($apbSrc . ":if (\$K = \"+\") do={ :do { /ip firewall address-list add list=\$List address=\$V timeout=\$Timeout comment=\"apb\" ; :set Total (\$Total + 1) } on-error={} }\r\n")
:set apbSrc ($apbSrc . ":if (\$K = \"c\") do={ :set NewCursor [:tonum \$V] }\r\n:if (\$K = \"n\") do={ :set Next [:tonum \$V] }\r\n}\r\n}\r\n")
:set apbSrc ($apbSrc . "} else={ :set Failed true ; :log warning (\"APB: rebuild got fetch status \" . (\$Res->\"status\")) }\r\n")
:set apbSrc ($apbSrc . "} else={ :set Failed true ; :log warning \"APB: rebuild got no reply from the server\" }\r\n}\r\n} while=((!\$Failed) && (\$Next > 0) && (\$Page < \$MaxPages))\r\n")
:set apbSrc ($apbSrc . ":if (\$Failed) do={\r\n:log error (\"APB: rebuild failed on page \" . \$Page . \", the sync script will retry. Run \" . \"apb-test\" . \" to see why.\")\r\n} else={\r\n")
:set apbSrc ($apbSrc . ":if (\$NewCursor >= 0) do={ :set apbCursor \$NewCursor }\r\n:log info (\"APB: rebuild complete, \" . \$Total . \" addresses, cursor \" . \$NewCursor)\r\n}\r\n")
:set apbSrc ($apbSrc . "} on-error={ :log error \"APB: rebuild script aborted\" }\r\n:set apbBootLock\r\n}\r\n")
:do { /system script remove [find name="apb-bootstrap"] } on-error={ :log debug "APB: no previous apb-bootstrap" }
/system script add name="apb-bootstrap" policy=read,write,test dont-require-permissions=no comment="APB: rebuilds the whole list after a reboot" source=$apbSrc

# --- apb-report: uploads locally detected addresses
:set apbSrc ""
:set apbSrc ($apbSrc . "# APB report for edge-1.\r\n# Uploads the addresses your own firewall rules have put into the detection\r\n")
:set apbSrc ($apbSrc . "# list. Already-reported addresses are tracked in a second RAM-only list, so\r\n# nothing is sent twice and nothing is written to flash.\r\n")
:set apbSrc ($apbSrc . ":local Url \"https://apb.example.org/api/v1\"\r\n:local Token \"apb_SAMPLETOKENONLY000000\"\r\n:local Detect \"APB_detect\"\r\n:local Sent \"APB_detect_sent\"\r\n")
:set apbSrc ($apbSrc . ":local UA \"apb-router\"\r\n:local SentTimeout 1d\r\n:local MaxBatch 300\r\n:global apbReportLock\r\n")
:set apbSrc ($apbSrc . ":local Hdr (\"Authorization: Bearer \" . \$Token . \",user-agent: \" . \$UA . \",X-Apb-Agent: \" . \$UA)\r\n:local Now [/system resource get uptime]\r\n")
:set apbSrc ($apbSrc . ":local Run true\r\n:if ([:typeof \$apbReportLock] = \"time\") do={ :if ((\$Now - \$apbReportLock) < 10m) do={ :set Run false } }\r\n:if (\$Run) do={\r\n")
:set apbSrc ($apbSrc . ":set apbReportLock \$Now\r\n:do {\r\n:local Payload \"\"\r\n:local Count 0\r\n:foreach Id in=[/ip firewall address-list find list=\$Detect] do={\r\n")
:set apbSrc ($apbSrc . ":if (\$Count < \$MaxBatch) do={\r\n:local A \"\"\r\n:do { :set A [/ip firewall address-list get \$Id address] } on-error={}\r\n:if ([:len \$A] > 0) do={\r\n")
:set apbSrc ($apbSrc . ":if ([:len [/ip firewall address-list find list=\$Sent address=\$A]] = 0) do={\r\n:if (\$Count > 0) do={ :set Payload (\$Payload . \",\") }\r\n")
:set apbSrc ($apbSrc . ":set Payload (\$Payload . \$A)\r\n:set Count (\$Count + 1)\r\n}\r\n}\r\n}\r\n}\r\n:if (\$Count > 0) do={\r\n")
:set apbSrc ($apbSrc . ":local Meta (\",Content-Type: text/plain,X-Apb-Identity: \" . [/system identity get name] . \",X-Apb-Ros: \" . [/system resource get version] . \",X-Apb-Model: \" . [/sys")
:set apbSrc ($apbSrc . "tem resource get board-name])\r\n:local Res \"\"\r\n")
:set apbSrc ($apbSrc . ":do { :set Res [/tool fetch url=(\$Url . \"/report\") http-method=post http-data=\$Payload http-header-field=(\$Hdr . \$Meta) mode=https check-certificate=yes-without-crl")
:set apbSrc ($apbSrc . " output=user as-value] } on-error={ :log warning (\"APB: report could not reach \" . \$Url . \" - run apb-test for detail\") }\r\n")
:set apbSrc ($apbSrc . ":if ([:typeof \$Res] = \"array\") do={\r\n:if ((\$Res->\"status\") = \"finished\") do={\r\n:local Data (\$Res->\"data\")\r\n:if ([:pick \$Data 0 2] = \"ok\") do={\r\n")
:set apbSrc ($apbSrc . ":foreach A in=[:toarray \$Payload] do={ :do { /ip firewall address-list add list=\$Sent address=\$A timeout=\$SentTimeout comment=\"apb-sent\" } on-error={} }\r\n")
:set apbSrc ($apbSrc . ":log info (\"APB: reported \" . \$Count . \" addresses\")\r\n} else={ :log warning (\"APB: report rejected: \" . \$Data) }\r\n}\r\n}\r\n}\r\n")
:set apbSrc ($apbSrc . "} on-error={ :log error \"APB: report script aborted\" }\r\n:set apbReportLock\r\n}\r\n")
:do { /system script remove [find name="apb-report"] } on-error={ :log debug "APB: no previous apb-report" }
/system script add name="apb-report" policy=read,write,test dont-require-permissions=no comment="APB: uploads locally detected addresses" source=$apbSrc

# --- apb-purge: clears every address APB manages here
:set apbSrc ""
:set apbSrc ($apbSrc . "# APB purge for edge-1.\r\n# Clears every address APB manages on this router and forgets the cursor, so\r\n")
:set apbSrc ($apbSrc . "# the next sync rebuilds from scratch. The scripts and schedules stay in place.\r\n:local List \"APB\"\r\n:local Sent \"APB_detect_sent\"\r\n:global apbCursor\r\n")
:set apbSrc ($apbSrc . ":global apbLock\r\n:global apbBootLock\r\n:global apbReportLock\r\n/ip firewall address-list remove [find list=\$List]\r\n")
:set apbSrc ($apbSrc . "/ip firewall address-list remove [find list=\$Sent]\r\n:set apbCursor\r\n:set apbLock\r\n:set apbBootLock\r\n:set apbReportLock\r\n")
:set apbSrc ($apbSrc . ":log info \"APB: local state cleared\"\r\n")
:do { /system script remove [find name="apb-purge"] } on-error={ :log debug "APB: no previous apb-purge" }
/system script add name="apb-purge" policy=read,write,test dont-require-permissions=no comment="APB: clears every address APB manages here" source=$apbSrc

# --- apb-test: one-shot connectivity check, run it by hand
:set apbSrc ""
:set apbSrc ($apbSrc . "# APB connectivity test for edge-1.\r\n# Run it by hand and read the log:\r\n#   /system script run apb-test\r\n#   /log print where message~\"APB test\"\r\n")
:set apbSrc ($apbSrc . "# It performs exactly one call and reports what came back, so a router that is\r\n# not syncing can be diagnosed without guessing.\r\n")
:set apbSrc ($apbSrc . ":local Url \"https://apb.example.org/api/v1\"\r\n:local Token \"apb_SAMPLETOKENONLY000000\"\r\n:local UA \"apb-router\"\r\n")
:set apbSrc ($apbSrc . ":local Hdr (\"Authorization: Bearer \" . \$Token . \",user-agent: \" . \$UA . \",X-Apb-Agent: \" . \$UA)\r\n:local Res \"\"\r\n")
:set apbSrc ($apbSrc . ":log info (\"APB test: GET \" . \$Url . \"/whoami as https, certificate check yes-without-crl\")\r\n")
:set apbSrc ($apbSrc . ":do { :set Res [/tool fetch url=(\$Url . \"/whoami\") http-method=get http-header-field=\$Hdr mode=https check-certificate=yes-without-crl output=user as-value] } on-erro")
:set apbSrc ($apbSrc . "r={ :log error \"APB test: fetch raised an error. The usual causes are a name that does not resolve, no route to the server, or a certificate the router will not accept.")
:set apbSrc ($apbSrc . "\" }\r\n:if ([:typeof \$Res] = \"array\") do={\r\n:log info (\"APB test: status \" . (\$Res->\"status\"))\r\n:log info (\"APB test: reply \" . (\$Res->\"data\"))\r\n")
:set apbSrc ($apbSrc . ":if ((\$Res->\"status\") = \"finished\") do={\r\n")
:set apbSrc ($apbSrc . ":if ([:pick (\$Res->\"data\") 0 2] = \"1,\") do={ :log info \"APB test: the server answered correctly, this router is configured and authorised\" } else={ :log error \"AP")
:set apbSrc ($apbSrc . "B test: the server answered but not with a configuration line, so the token is probably wrong or revoked\" }\r\n}\r\n} else={\r\n")
:set apbSrc ($apbSrc . ":log error \"APB test: no reply at all. Nothing reached the server.\"\r\n}\r\n")
:do { /system script remove [find name="apb-test"] } on-error={ :log debug "APB: no previous apb-test" }
/system script add name="apb-test" policy=read,write,test dont-require-permissions=no comment="APB: one-shot connectivity check, run it by hand" source=$apbSrc

:set apbSrc ""

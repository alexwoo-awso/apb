# APB scripts for "edge-1" (RouterOS v7)
# Generated 2026-09-02 19:02:42Z by APB.
#
# This file contains the API token for this router. Treat it as a password:
# do not commit it, do not share it, and remove the file from the router once
# the import has finished. If it leaks, revoke the token in the console and
# issue a new one.
#
# Import with:  /import file-name=<this file>
:do { /system script remove [find name~"^apb-"] } on-error={}
/system script add name="apb-sync" policy=read,write,test dont-require-permissions=no comment="APB: applies incremental blocklist changes" source="# APB incremental sync for edge-1.\r\n# Applies the changes the server has queued since the curs\
    or held in RAM.\r\n# Entries are added with a timeout so RouterOS keeps them in memory and n\
    ever\r\n# writes them to flash.\r\n:local Url \"https://apb.example.org/api/v1\"\r\n:local T\
    oken \"apb_SAMPLETOKENONLY000000\"\r\n:local List \"APB\"\r\n:local UA \"apb-router\"\r\n:lo\
    cal Timeout 520w\r\n:local MaxLoops 20\r\n:global apbCursor\r\n:global apbLock\r\n:local Hdr\
     (\"Authorization: Bearer \" . \$Token . \",User-Agent: \" . \$UA)\r\n:local Now [/system re\
    source get uptime]\r\n:local Run true\r\n:if ([:typeof \$apbLock] = \"time\") do={ :if ((\$N\
    ow - \$apbLock) < 3m) do={ :set Run false } }\r\n:if (\$Run) do={\r\n:set apbLock \$Now\r\n:\
    do {\r\n:if ([:typeof \$apbCursor] != \"num\") do={\r\n:log info \"APB: no cursor in memory,\
     rebuilding the list\"\r\n/system script run apb-bootstrap\r\n} else={\r\n:local More true\r\
    \n:local Loops 0\r\n:do {\r\n:set More false\r\n:set Loops (\$Loops + 1)\r\n:local Held [:le\
    n [/ip firewall address-list find list=\$List]]\r\n:local Res \"\"\r\n:do { :set Res [/tool \
    fetch url=(\$Url . \"/sync\?c=\" . \$apbCursor . \"&n=\" . \$Held) http-method=get http-head\
    er-field=\$Hdr check-certificate=yes-without-crl output=user as-value] } on-error={ :log war\
    ning \"APB: sync request failed\" }\r\n:if ([:typeof \$Res] = \"array\") do={\r\n:if ((\$Res\
    ->\"status\") = \"finished\") do={\r\n:local Next -1\r\n:local Resync false\r\n:local Added \
    0\r\n:local Removed 0\r\n:foreach Tok in=[:toarray (\$Res->\"data\")] do={\r\n:if ([:len \$T\
    ok] > 1) do={\r\n:local K [:pick \$Tok 0 1]\r\n:local V [:pick \$Tok 1 [:len \$Tok]]\r\n:if \
    (\$K = \"+\") do={ :if ([:typeof [:find \$V \":\"]] = \"num\") do={ :if ([:len [/ipv6 firewa\
    ll address-list find list=\$List address=\$V]] = 0) do={ :do { /ipv6 firewall address-list a\
    dd list=\$List address=\$V timeout=\$Timeout comment=\"apb\" ; :set Added (\$Added + 1) } on\
    -error={} } } else={ :if ([:len [/ip firewall address-list find list=\$List address=\$V]] = \
    0) do={ :do { /ip firewall address-list add list=\$List address=\$V timeout=\$Timeout commen\
    t=\"apb\" ; :set Added (\$Added + 1) } on-error={} } } }\r\n:if (\$K = \"-\") do={ :if ([:ty\
    peof [:find \$V \":\"]] = \"num\") do={ :do { /ipv6 firewall address-list remove [find list=\
    \$List address=\$V] ; :set Removed (\$Removed + 1) } on-error={} } else={ :do { /ip firewall\
     address-list remove [find list=\$List address=\$V] ; :set Removed (\$Removed + 1) } on-erro\
    r={} } }\r\n:if (\$K = \"c\") do={ :set Next [:tonum \$V] }\r\n:if (\$K = \"m\") do={ :set M\
    ore true }\r\n:if (\$K = \"r\") do={ :set Resync true }\r\n}\r\n}\r\n:if (\$Resync) do={\r\n\
    :log info \"APB: cursor too old, falling back to a full rebuild\"\r\n:set More false\r\n/sys\
    tem script run apb-bootstrap\r\n} else={\r\n:if (\$Next >= 0) do={ :set apbCursor \$Next }\r\
    \n:if ((\$Added + \$Removed) > 0) do={ :log info (\"APB: applied +\" . \$Added . \" -\" . \$\
    Removed . \", cursor \" . \$apbCursor) }\r\n}\r\n}\r\n}\r\n} while=(\$More && (\$Loops < \$M\
    axLoops))\r\n}\r\n} on-error={ :log error \"APB: sync script aborted\" }\r\n:set apbLock\r\n\
    }\r\n"
/system script add name="apb-bootstrap" policy=read,write,test dont-require-permissions=no comment="APB: rebuilds the whole list after a reboot" source="# APB full rebuild for edge-1.\r\n# The blocklist lives in RAM, so it is empty after a reboot. T\
    his script pulls\r\n# the whole list back in pages small enough for the fetch buffer and sto\
    res the\r\n# server cursor so the incremental sync can take over.\r\n# It also runs when the\
     server reports that the cursor is too old to catch up.\r\n:local Url \"https://apb.example.\
    org/api/v1\"\r\n:local Token \"apb_SAMPLETOKENONLY000000\"\r\n:local List \"APB\"\r\n:local \
    UA \"apb-router\"\r\n:local Timeout 520w\r\n:local MaxPages 500\r\n:global apbCursor\r\n:glo\
    bal apbBootLock\r\n:local Hdr (\"Authorization: Bearer \" . \$Token . \",User-Agent: \" . \$\
    UA)\r\n:local Now [/system resource get uptime]\r\n:local Run true\r\n:if ([:typeof \$apbBoo\
    tLock] = \"time\") do={ :if ((\$Now - \$apbBootLock) < 30m) do={ :set Run false } }\r\n:if (\
    \$Run) do={\r\n:set apbBootLock \$Now\r\n:do {\r\n:local Next 0\r\n:local Page 0\r\n:local N\
    ewCursor -1\r\n:local Total 0\r\n:local Failed false\r\n:local Started false\r\n:do {\r\n:se\
    t Page (\$Page + 1)\r\n:local U (\$Url . \"/full\")\r\n:if (\$Next > 0) do={ :set U (\$U . \
    \"\?a=\" . \$Next) }\r\n:set Next 0\r\n:local Res \"\"\r\n:do { :set Res [/tool fetch url=\$\
    U http-method=get http-header-field=\$Hdr check-certificate=yes-without-crl output=user as-v\
    alue] } on-error={ :set Failed true }\r\n:if (!\$Failed) do={\r\n:if ([:typeof \$Res] = \"ar\
    ray\") do={\r\n:if ((\$Res->\"status\") = \"finished\") do={\r\n:if (!\$Started) do={\r\n:se\
    t Started true\r\n:set apbCursor\r\n/ip firewall address-list remove [find list=\$List] ; /i\
    pv6 firewall address-list remove [find list=\$List]\r\n}\r\n:foreach Tok in=[:toarray (\$Res\
    ->\"data\")] do={\r\n:if ([:len \$Tok] > 1) do={\r\n:local K [:pick \$Tok 0 1]\r\n:local V [\
    :pick \$Tok 1 [:len \$Tok]]\r\n:if (\$K = \"+\") do={ :if ([:typeof [:find \$V \":\"]] = \"n\
    um\") do={ :do { /ipv6 firewall address-list add list=\$List address=\$V timeout=\$Timeout c\
    omment=\"apb\" ; :set Total (\$Total + 1) } on-error={} } else={ :do { /ip firewall address-\
    list add list=\$List address=\$V timeout=\$Timeout comment=\"apb\" ; :set Total (\$Total + 1\
    ) } on-error={} } }\r\n:if (\$K = \"c\") do={ :set NewCursor [:tonum \$V] }\r\n:if (\$K = \"\
    n\") do={ :set Next [:tonum \$V] }\r\n}\r\n}\r\n} else={ :set Failed true }\r\n} else={ :set\
     Failed true }\r\n}\r\n} while=((!\$Failed) && (\$Next > 0) && (\$Page < \$MaxPages))\r\n:if\
     (\$Failed) do={\r\n:log error \"APB: rebuild failed, the sync script will retry\"\r\n} else\
    ={\r\n:if (\$NewCursor >= 0) do={ :set apbCursor \$NewCursor }\r\n:log info (\"APB: rebuild \
    complete, \" . \$Total . \" addresses, cursor \" . \$NewCursor)\r\n}\r\n} on-error={ :log er\
    ror \"APB: rebuild script aborted\" }\r\n:set apbBootLock\r\n}\r\n"
/system script add name="apb-report" policy=read,write,test dont-require-permissions=no comment="APB: uploads locally detected addresses" source="# APB report for edge-1.\r\n# Uploads the addresses your own firewall rules have put into the de\
    tection\r\n# list. Already-reported addresses are tracked in a second RAM-only list, so\r\n#\
     nothing is sent twice and nothing is written to flash.\r\n:local Url \"https://apb.example.\
    org/api/v1\"\r\n:local Token \"apb_SAMPLETOKENONLY000000\"\r\n:local Detect \"APB_detect\"\r\
    \n:local Sent \"APB_detect_sent\"\r\n:local UA \"apb-router\"\r\n:local SentTimeout 1d\r\n:l\
    ocal MaxBatch 300\r\n:global apbReportLock\r\n:local Hdr (\"Authorization: Bearer \" . \$Tok\
    en . \",User-Agent: \" . \$UA)\r\n:local Now [/system resource get uptime]\r\n:local Run tru\
    e\r\n:if ([:typeof \$apbReportLock] = \"time\") do={ :if ((\$Now - \$apbReportLock) < 10m) d\
    o={ :set Run false } }\r\n:if (\$Run) do={\r\n:set apbReportLock \$Now\r\n:do {\r\n:local Pa\
    yload \"\"\r\n:local Count 0\r\n:foreach Id in=[/ip firewall address-list find list=\$Detect\
    ] do={\r\n:if (\$Count < \$MaxBatch) do={\r\n:local A \"\"\r\n:do { :set A [/ip firewall add\
    ress-list get \$Id address] } on-error={}\r\n:if ([:len \$A] > 0) do={\r\n:if ([:len [/ip fi\
    rewall address-list find list=\$Sent address=\$A]] = 0) do={\r\n:if (\$Count > 0) do={ :set \
    Payload (\$Payload . \",\") }\r\n:set Payload (\$Payload . \$A)\r\n:set Count (\$Count + 1)\
    \r\n}\r\n}\r\n}\r\n}\r\n:if (\$Count > 0) do={\r\n:local Meta (\",Content-Type: text/plain,X\
    -Apb-Identity: \" . [/system identity get name] . \",X-Apb-Ros: \" . [/system resource get v\
    ersion] . \",X-Apb-Model: \" . [/system resource get board-name])\r\n:local Res \"\"\r\n:do \
    { :set Res [/tool fetch url=(\$Url . \"/report\") http-method=post http-data=\$Payload http-\
    header-field=(\$Hdr . \$Meta) check-certificate=yes-without-crl output=user as-value] } on-e\
    rror={ :log warning \"APB: report request failed\" }\r\n:if ([:typeof \$Res] = \"array\") do\
    ={\r\n:if ((\$Res->\"status\") = \"finished\") do={\r\n:local Data (\$Res->\"data\")\r\n:if \
    ([:pick \$Data 0 2] = \"ok\") do={\r\n:foreach A in=[:toarray \$Payload] do={ :do { /ip fire\
    wall address-list add list=\$Sent address=\$A timeout=\$SentTimeout comment=\"apb-sent\" } o\
    n-error={} }\r\n:log info (\"APB: reported \" . \$Count . \" addresses\")\r\n} else={ :log w\
    arning (\"APB: report rejected: \" . \$Data) }\r\n}\r\n}\r\n}\r\n} on-error={ :log error \"A\
    PB: report script aborted\" }\r\n:set apbReportLock\r\n}\r\n"
/system script add name="apb-purge" policy=read,write,test dont-require-permissions=no comment="APB: clears every address APB manages here" source="# APB purge for edge-1.\r\n# Clears every address APB manages on this router and forgets the cur\
    sor, so\r\n# the next sync rebuilds from scratch. The scripts and schedules stay in place.\r\
    \n:local List \"APB\"\r\n:local Sent \"APB_detect_sent\"\r\n:global apbCursor\r\n:global apb\
    Lock\r\n:global apbBootLock\r\n:global apbReportLock\r\n/ip firewall address-list remove [fi\
    nd list=\$List] ; /ipv6 firewall address-list remove [find list=\$List]\r\n/ip firewall addr\
    ess-list remove [find list=\$Sent]\r\n:set apbCursor\r\n:set apbLock\r\n:set apbBootLock\r\n\
    :set apbReportLock\r\n:log info \"APB: local state cleared\"\r\n"

:do { /system scheduler remove [find name~"^apb-"] } on-error={}
/system scheduler add name="apb-sync" interval=15s start-time=startup policy=read,write,test comment="APB: poll for changes" on-event="/system script run apb-sync"
/system scheduler add name="apb-report" interval=300s start-time=startup policy=read,write,test comment="APB: upload detections" on-event="/system script run apb-report"
/system scheduler add name="apb-boot" interval=0 start-time=startup policy=read,write,test comment="APB: rebuild the RAM-held list after a reboot" on-event="/system script run apb-bootstrap"

# Build the list immediately instead of waiting for the first schedule.
/system script run apb-bootstrap

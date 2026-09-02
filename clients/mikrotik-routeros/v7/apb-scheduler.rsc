# APB scheduler for "edge-1" (RouterOS v7)
# Generated 2026-09-02 19:02:42Z by APB.
#
# Import with:  /import file-name=<this file>
:do { /system scheduler remove [find name~"^apb-"] } on-error={}
/system scheduler add name="apb-sync" interval=15s start-time=startup policy=read,write,test comment="APB: poll for changes" on-event="/system script run apb-sync"
/system scheduler add name="apb-report" interval=300s start-time=startup policy=read,write,test comment="APB: upload detections" on-event="/system script run apb-report"
/system scheduler add name="apb-boot" interval=0 start-time=startup policy=read,write,test comment="APB: rebuild the RAM-held list after a reboot" on-event="/system script run apb-bootstrap"

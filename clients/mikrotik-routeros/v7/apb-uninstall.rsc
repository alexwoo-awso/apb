# APB uninstall for "edge-1" (RouterOS v7)
# Generated 2026-09-02 19:02:42Z by APB.
#
# Import with:  /import file-name=<this file>
:do { /system script run apb-purge } on-error={}
:do { /system scheduler remove [find name~"^apb-"] } on-error={}
:do { /system script remove [find name~"^apb-"] } on-error={}
:log info "APB: removed"

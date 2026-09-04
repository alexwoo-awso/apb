# APB uninstall for "edge-1" (RouterOS v7)
# Generated 2026-09-04 00:53:47Z by APB.
#
# Import with:  /import file-name=<this file>
:do { /system script run apb-purge } on-error={ :log warning "APB: purge failed" }
:do { /system scheduler remove [find name="apb-sync"] } on-error={ :log debug "APB: no previous apb-sync" }
:do { /system scheduler remove [find name="apb-report"] } on-error={ :log debug "APB: no previous apb-report" }
:do { /system scheduler remove [find name="apb-boot"] } on-error={ :log debug "APB: no previous apb-boot" }
:do { /system script remove [find name="apb-sync"] } on-error={ :log debug "APB: no previous apb-sync" }
:do { /system script remove [find name="apb-bootstrap"] } on-error={ :log debug "APB: no previous apb-bootstrap" }
:do { /system script remove [find name="apb-report"] } on-error={ :log debug "APB: no previous apb-report" }
:do { /system script remove [find name="apb-purge"] } on-error={ :log debug "APB: no previous apb-purge" }
:do { /system script remove [find name="apb-test"] } on-error={ :log debug "APB: no previous apb-test" }
:log info "APB: removed"

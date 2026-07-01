package openshell.sandbox

default allow_network = false

# Static policy data passthrough (queried at sandbox startup).
filesystem_policy := data.filesystem_policy
landlock_policy := data.landlock
process_policy := data.process

allow_network if { network_policy_for_request }
network_policy_for_request if { false }

default network_action := "deny"
default allow_request = false

# @summary 
#    Ensure TIPC is disabled 
#
# The Transparent Inter-Process Communication (TIPC) protocol is designed to provide 
# communication between cluster nodes.
#
# Rationale:
# If the protocol is not being used, it is recommended that kernel module not be loaded, disabling 
# the service to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_tipc':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_tipc (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'debian' and
    $facts['os']['release']['major'] > '10' {
      $command = '/bin/false'
      kmod::blacklist { 'tipc': }
    } else {
      $command = '/bin/true'
    }

    kmod::install { 'tipc':
      command => $command,
    }
  }
}

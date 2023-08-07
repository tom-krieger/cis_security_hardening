# @summary 
#    Ensure RDS is disabled 
#
# The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide 
# low-latency, high-bandwidth communications between cluster nodes. It was developed by the 
# Oracle Corporation.
#
# Rationale:
# If the protocol is not being used, it is recommended that kernel module not be loaded, disabling 
# the service to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_rds':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_rds (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'debian' and
    $facts['os']['release']['major'] > '10' {
      $command = '/bin/false'
      kmod::blacklist { 'rds': }
    } else {
      $command = '/bin/true'
    }

    kmod::install { 'rds':
      command => $command,
    }
  }
}

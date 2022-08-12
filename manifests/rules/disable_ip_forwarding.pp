# @summary 
#    Ensure IP forwarding is disabled (Automated)
#
# The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets or not.
#
# Rationale:
# Setting the flag to 0 ensures that a system with multiple interfaces (for example, a hard proxy), 
# will never be able to forward packets, and therefore, never serve as a router.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_ip_forwarding':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_ip_forwarding (
  Boolean $enforce = false,
) {
  if $enforce {
    Sysctl {
      'net.ipv4.ip_forward':
        value => 0,
    }
    if  fact('network6') != undef {
      Sysctl {
        'net.ipv6.conf.all.forwarding':
          value => 0,
      }
    }
  }
}

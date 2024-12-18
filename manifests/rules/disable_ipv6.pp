# @summary 
#    Disable IPv6 
#
# Although IPv6 has many advantages over IPv4, not all organizations have IPv6 or dual stack configurations implemented.
#
# Rationale:
# If IPv6 or dual stack is not to be used, it is recommended that IPv6 be disabled to reduce the attack surface of the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_ipv6':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_ipv6 (
  Boolean $enforce = false,
) {
  if $enforce {
    kernel_parameter { 'ipv6.disable':
      value => '1',
    }

    if fact('network6') != undef {
      sysctl { 'net.ipv6.conf.all.disable_ipv6':
        ensure => present,
        value  => 1,
      }
      sysctl { 'net.ipv6.conf.default.disable_ipv6':
        ensure => present,
        value  => 1,
      }
    }
  }
}

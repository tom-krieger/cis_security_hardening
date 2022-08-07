# @summary 
#    Ensure IPv6 router advertisements are not accepted (Manual)
#
# This setting disables the system's ability to accept IPv6 router advertisements.
#
# Rationale:
# It is recommended that systems not accept router advertisements as they could be tricked into routing 
# traffic to compromised machines. Setting hard routes within the system (usually a single default route 
# to a trusted router) protects the system from bad routes.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class  { 'cis_security_hardening::rules::ipv6_router_advertisements':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ipv6_router_advertisements (
  Boolean $enforce = false,
) {
  if $enforce and fact('network6') != undef {
    Sysctl {
      'net.ipv6.conf.all.accept_ra':
        value => 0,
    }
    Sysctl {
      'net.ipv6.conf.default.accept_ra':
        value => 0,
    }
  }
}

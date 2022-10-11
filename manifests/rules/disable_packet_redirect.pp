# @summary 
#    Ensure packet redirect sending is disabled 
#
# ICMP Redirects are used to send routing information to other hosts. As a host itself does not act 
# as a router (in a host only configuration), there is no need to send redirects.
#
# Rationale:
# An attacker could use a compromised host to send invalid ICMP redirects to other router devices in 
# an attempt to corrupt routing and have users access a system set up by the attacker as opposed to 
# a valid system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_packet_redirect':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_packet_redirect (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.ipv4.conf.all.send_redirects':
        value => 0,
    }
    sysctl {
      'net.ipv4.conf.default.send_redirects':
        value => 0,
    }
  }
}

# @summary 
#    Ensure secure ICMP redirects are not accepted 
#
# Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed 
# on the default gateway list. It is assumed that these gateways are known to your system, and 
# that they are likely to be secure.
# 
# Rationale:
# It is still possible for even known gateways to be compromised. Setting 
# net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by 
# possibly compromised known gateways.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::secure_icmp_redirects':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::secure_icmp_redirects (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.ipv4.conf.all.secure_redirects':
        ensure => present,
        value  => 0,
    }
    sysctl {
      'net.ipv4.conf.default.secure_redirects':
        ensure => present,
        value  => 0,
    }
  }
}

# @summary 
#    Ensure Reverse Path Filtering is enabled 
#
# Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces 
# the Linux kernel to utilize reverse path filtering on a received packet to determine 
# if the packet was valid. Essentially, with reverse path filtering, if the return packet 
# does not go out the same interface that the corresponding source packet came from, the 
# packet is dropped (and logged if log_martians is set).
#
# Rationale:
# Setting these flags is a good way to deter attackers from sending your system bogus packets 
# that cannot be responded to. One instance where this feature breaks down is if asymmetrical 
# routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) 
# on your system. If you are using asymmetrical routing on your system, you will not be able 
# to enable this feature without breaking the routing.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::enable_reverse_path_filtering {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::enable_reverse_path_filtering (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.ipv4.conf.all.rp_filter':
        ensure => present,
        value  => 1,
    }
    sysctl {
      'net.ipv4.conf.default.rp_filter':
        ensure => present,
        value  => 1,
    }
  }
}

# @summary 
#    Ensure bogus ICMP responses are ignored 
#
# Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus 
# responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from 
# filling up with useless log messages.
#
# Rationale:
# Some routers (and some attackers) will send responses that violate RFC-1122 and attempt 
# to fill up a log file system with many useless error messages.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::ignore_bogus_icmp_responses':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ignore_bogus_icmp_responses (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.ipv4.icmp_ignore_bogus_error_responses':
        ensure => present,
        value  => 1,
    }
  }
}

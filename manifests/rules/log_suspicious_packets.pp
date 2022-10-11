# @summary 
#    Ensure suspicious packets are logged 
#
# When enabled, this feature logs packets with un-routable source addresses to the kernel log.
#
# Rationale:
# Enabling this feature and logging these packets allows an administrator to investigate the possibility 
# that an attacker is sending spoofed packets to their system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::log_suspicious_packets':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::log_suspicious_packets (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.ipv4.conf.all.log_martians':
        value => 1,
    }
    sysctl {
      'net.ipv4.conf.default.log_martians':
        value => 1,
    }
  }
}

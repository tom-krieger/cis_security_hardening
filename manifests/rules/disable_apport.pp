# @summary
#    Ensure Automatic Error Reporting is not enabled (Automated)
#
# The Apport Error Reporting Service automatically generates crash reports for debugging.
#
# Rationale:
# Apport collects potentially sensitive data, such as core dumps, stack traces, and log files. They can contain passwords, credit 
# card numbers, serial numbers, and other private material.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::disable_apport':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_apport (
  Boolean $enforce = false,
) {
  if $enforce {
    if cis_security_hardening::hash_key($facts['cis_security_hardening'], 'apport') and
    cis_security_hardening::hash_key($facts['cis_security_hardening']['apport'], 'service') and
    $facts['cis_security_hardening']['apport']['service'] == true {
      service { 'apport.service':
        ensure => stopped,
        enable => false,
      }
    }

    if cis_security_hardening::hash_key($facts['cis_security_hardening'], 'apport') and
    cis_security_hardening::hash_key($facts['cis_security_hardening']['apport'], 'pkg') and
    $facts['cis_security_hardening']['apport']['pkg'] == true {
      $ensure = $facts['os']['family'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }
      ensure_packages('apport', {
          ensure => $ensure,
      })
    }
  }
}

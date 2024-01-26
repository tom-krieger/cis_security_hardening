# @summary
#    Ensure Automatic Error Reporting is not enabled (Automated)
#
# The Apport Error Reporting Service automatically generates crash reports for debugging
#
# Rationale:
# Apport collects potentially sensitive data, such as core dumps, stack traces, and log files. They can contain passwords, 
# credit card numbers, serial numbers, and other private material.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
#
# @example
#   class { 'cis_security_hardening::rules::automatic_error_reporting':   
#             enforce => true,
#   }
#
class cis_security_hardening::rules::automatic_error_reporting (
  Boolean $enforce = false,
) {
  $apport = fact('cis_security_hardening.apport.installed')
  if $enforce and $apport {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['apport'], {
        ensure => $ensure,
    })
  }
}

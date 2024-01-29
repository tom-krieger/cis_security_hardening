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
# @param delete_package
#    If set to trur apport package will be removed, otherwise onle the service gets stopped and masked
#
#
# @example
#   class { 'cis_security_hardening::rules::automatic_error_reporting':   
#             enforce => true,
#   }
#
class cis_security_hardening::rules::automatic_error_reporting (
  Boolean $enforce = false,
  Boolean $delete_package = false,
) {
  $apport = fact('cis_security_hardening.apport.installed')
  if $enforce and $apport {
    ensure_resource('service', ['apport'], {
        ensure => 'stopped',
        enable => false,
    })

    exec { 'mask apport daemon':
      command => 'systemctl mask apport',
      path    => ['/bin', '/usr/bin'],
      onlyif  => 'test $(systemctl is-enabled apport) = "enabled"',
    }

    if $delete_package {
      $ensure = $facts['os']['family'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }

      ensure_packages(['apport'], {
          ensure => $ensure,
      })
    }
  }
}

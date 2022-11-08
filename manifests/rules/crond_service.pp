# @summary 
#    Ensure cron daemon is enabled and running 
#
# The cron daemon is used to execute batch jobs on the system.
#
# Rationale:
# While there may not be user jobs that need to be run on the system, the system does have 
# maintenance jobs that may include security monitoring that have to run. If another method 
# for scheduling tasks is not being used, cron is used to execute them, and needs to be enabled 
# and running.
#
# @param enforce
#    Enforce the rule
#
# @param uninstall_cron
#    uninstall cron from the system
#
# @example
#   class { 'cis_security_hardening::rules::crond_service':
#       enforce => true,
#       uninstall_cron => false
#   }
#
# @api private
class cis_security_hardening::rules::crond_service (
  Boolean $enforce        = false,
  Boolean $uninstall_cron = false,
) {
  if $enforce {
    if $facts['os']['family'].downcase() == 'suse' {
      $ensure = 'absent'
    } else {
      $ensure = 'purged'
    }

    if $uninstall_cron {
      ensure_packages(['cronie'], {
          ensure => $ensure,
      })
    } else {
      $srv = $facts['os']['family'].downcase() ? {
        'debian' => 'cron',
        'suse'   => 'cron',
        default  => 'crond',
      }

      ensure_resource('service', $srv, {
          ensure => running,
          enable => true,
      })
    }
  }
}

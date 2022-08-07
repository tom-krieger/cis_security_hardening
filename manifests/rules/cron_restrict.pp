# @summary 
#    Ensure cron is restricted to authorized users (Automated)
#
# If cron is installed in the system, configure /etc/cron.allow to allow specific users to use these services. 
# If /etc/cron.allow does not exist, then /etc/cron.deny is checked. Any user not specifically defined in those 
# files is allowed to use cron. By removing the file, only users in /etc/cron.allow are allowed to use cron.
#
# Note: Even though a given user is not listed in cron.allow, cron jobs can still be run as that user. The 
# cron.allow file only controls administrative access to the crontab command for scheduling and modifying cron jobs.
#
# Rationale:
# On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to 
# control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny 
# list, you could potentially add a user ID to the system and forget to add it to the deny files..
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::cron_restrict':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::cron_restrict (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/cron.allow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/cron.deny':
      ensure => absent,
    }
  }
}

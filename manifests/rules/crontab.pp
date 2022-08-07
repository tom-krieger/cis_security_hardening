# @summary 
#    Ensure permissions on /etc/crontab are configured (Automated)
#
# The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root 
# is the user and group owner of the file and that only the owner can access the file.
# 
# Rationale:
# This file contains information on what system jobs are run by cron. Write access to these files could provide 
# unprivileged users with the ability to elevate their privileges. Read access to these files could provide users 
# with the ability to gain insight on system jobs that run on the system and could provide them a way to gain 
# unauthorized privileged access.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::crontab':
#       enforce => true,
#   }
#
# @api private 
class cis_security_hardening::rules::crontab (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/crontab':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }
}

# @summary 
#    Ensure permissions on /etc/cron.hourly are configured 
#
# This directory contains system cron jobs that need to run on an hourly basis. The files in this 
# directory cannot be manipulated by the crontab command, but are instead edited by system administrators 
# using a text editor. The commands below restrict read/write and search access to user and group root, 
# preventing regular users from accessing this directory.
#
# Rationale:
# Granting write access to this directory for non-privileged users could provide them the means for gaining 
# unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user 
# insight in how to gain elevated privileges or circumvent auditing controls.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::cron_hourly':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::cron_hourly (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/cron.hourly':
      ensure => directory,
      owner  => 'root',
      group  => 'root',
      mode   => '0700',
    }
  }
}

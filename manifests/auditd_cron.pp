# @summary 
#    Create a cron job to search privileged commands for auditd
#
# Auditd rules can monitor privileged command use. As filesystems cn be huge and searching
# the relevant commands can be time consuming this cron job will create a custom fact to
# provide the auditd rule with appriate imput.
#
# @param dirs_to_include
#    A list of directories to search
# @param start_time_minute
#    The minute to start the cronjob
# @param start_time_hour
#    The hour to run the cronjob
# @param cron_repeat
#    Interval to repeat the cronjob in hours. 0 means run only once a day.
# @param output_file
#    File to write fact data.
# @param script
#    Filename of the script to riun from cron.
#
# @example
#   include cis_security_hardening::auditd_cron
class cis_security_hardening::auditd_cron (
  Array $dirs_to_include                  = ['/usr'],
  Integer $start_time_minute              = 37,
  Integer $start_time_hour                = 3,
  Enum['0','2','4','6','8'] $cron_repeat  = 0,
  Stdlib::Absolutepath $output_file       = '/opt/puppetlabs/facter/facts.d/cis_security_hardening_auditd_priv_cmds.yaml',
  Stdlib::Absolutepath $script            = '/usr/share/cis_security_hardening/bin/auditd_priv_cmds.sh',
) {
  if ! empty($dirs_to_include) {
    file { '/etc/cron.d/auditd_priv_commands.cron':
      ensure  => file,
      content => epp('cis_security_hardening/auditd_priv_cmds.cron.epp', {
          minute      => $start_time_minute,
          hour        => $start_time_hour,
          cron_repeat => $cron_repeat,
          script      => $script,
      }),
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }

    file { $script:
      ensure  => file,
      content => epp('cis_security_hardening/auditd_priv_cmds.epp', {
          output_file     => $output_file,
          dirs_to_include => $dirs_to_include,
      }),
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
    }
  }
}

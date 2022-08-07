 # @summary 
#    Security baseline enforcement and monitoring
#
# Define a complete security baseline and monitor the rules. The definition of the baseline can be done in Hiera. 
# The purpose of the module is to give the ability to setup complete security baseline which not necessarily have to stick 
# to an industry security guide like the CIS benchmarks.  
# One main purpose is to ensure the module can be extended by further security settings and monitorings without changing the code of
# this module.
#
# The easiest way to use the module is to put all rule data into a hiera file. For more information please coinsult the README file.
#
# @param profile
#    The benchmark profile to use. Currently only server profiles are supported.
#
# @param level
#    The CIS Benchmark server security level
#
# @param update_postrun_command
#    Update Puppet agent post run command
#
# @param fact_upload_command
#    Command to use to upload facts to Puppet master
#
# @param exclude_dirs_sticky_ww
#    Araay of directories to exclude from the search for world writable directories with sticky bit
#
# @param auditd_suid_include
#    Directories to search for suid and sgid programs. Can not be set together with auditd_suid_exclude
#
# @param auditd_suid_exclude
#    Directories to exclude from search for suid and sgid programs. Can not be set together with auditd_suid_include
#
# @param auditd_rules_fact_file
#    The file where to store the facts for auditd rules
#
# @param time_until_reboot
#    Time to wait until system is rebooted if required. Time in seconds.
#
# @param verbose_logging
#    Print various info messages
#
# @example
#   include cis_security_hardening
class cis_security_hardening (
  Enum['server'] $profile           = 'server',
  Enum['1', '2'] $level             = '2',
  Array $exclude_dirs_sticky_ww     = [],
  Boolean $update_postrun_command   = true,
  String $fact_upload_command       = '/usr/share/cis_security_hardening/bin/fact_upload.sh',
  Array $auditd_suid_include        = ['/usr'],
  Array $auditd_suid_exclude        = [],
  String $auditd_rules_fact_file    = '/opt/puppetlabs/facter/facts.d/cis_security_hardening_auditd.yaml',
  Integer $time_until_reboot        = 120,
  Boolean $verbose_logging          = false,
) {
  class { 'cis_security_hardening::services':
    time_until_reboot => $time_until_reboot,
  }

  class { 'cis_security_hardening::sticky_world_writable_cron':
    dirs_to_exclude => $exclude_dirs_sticky_ww,
  }

  class { 'cis_security_hardening::config':
    update_postrun_command => $update_postrun_command,
    fact_upload_command    => $fact_upload_command,
  }

  $os = $facts['operatingsystem'].downcase()

  $os_vers = $os ? {
    'ubuntu' => split($facts['operatingsystemmajrelease'], '[.]')[0],
    default => $facts['operatingsystemmajrelease'],
  }

  $key = "cis_security_hardening::benchmark::${os}::${os_vers}"
  $benchmark = lookup($key, undef, undef, {})

  if has_key($benchmark, 'bundles') {
    $benchmark['bundles'].each |$bundle, $bundle_data| {
      if has_key($bundle_data, 'level1') {
        $level1 = $bundle_data['level1']
      } else {
        $level1 = []
      }

      if has_key($bundle_data, 'level2') {
        $level2 = $bundle_data['level2']
      } else {
        $level2 = []
      }

      if $level == '2' {
        $rules = concat($level1, $level2)
      } else {
        $rules = $level1
      }

      if $verbose_logging {
        echo { "cis_security_hardening applying bundle ${bundle}":
          message  => "cis_security_hardening applying bundle ${bundle}",
          loglevel => 'info',
          withpath => false,
        }
      }

      $rules.each |$rule| {
        $class = "cis_security_hardening::rules::${rule}"
        include $class
      }
    }
  } else {
    echo { 'no bundles':
      message  => "No bundles found, enforcing nothing. (${key})",
      loglevel => 'warning',
      withpath => false,
    }
  }
}

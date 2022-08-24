 # @summary 
#    Security baseline enforcement
#
# Define a complete security baseline and monitor the rules. The definition of the baseline can be done in Hiera. 
# The purpose of the module is to give the ability to setup complete security baseline which not necessarily have to stick 
# to an industry security guide like the CIS benchmarks.
#
# The easiest way to use the module is to put all rule data into a hiera file. For more information please coinsult the README file.
#
# @param profile
#    The benchmark profile to use. Currently only server profiles are supported.
#
# @param level
#    The CIS Benchmark server security level. Higher levels include all rules of lover levels. Therefore level1 rules are all included
#    in the level2 rules and stig includes level1 nd level 2 rules.
#
# @param update_postrun_command
#    Update Puppet agent post run command
# @param base_dir
#    The base directory where all scripts and so on go.
# @param fact_upload_command
#    Command to use to upload facts to Puppet master
# @param exclude_dirs_sticky_ww
#    Araay of directories to exclude from the search for world writable directories with sticky bit
# @param auditd_dirs_to_include
#    Directories to search for privileged commands to create auditd rules.
# @param time_until_reboot
#    Time to wait until system is rebooted if required. Time in seconds.
# @param verbose_logging
#    Print various info messages
#
# @example
#   include cis_security_hardening
class cis_security_hardening (
  Enum['server'] $profile                   = 'server',
  Enum['1', '2', 'stig'] $level             = '2',
  Array $exclude_dirs_sticky_ww             = [],
  Array $auditd_dirs_to_include             = ['/usr'],
  Boolean $update_postrun_command           = true,
  Stdlib::Absolutepath $fact_upload_command = "${base_dir}/bin/fact_upload.sh",
  Integer $time_until_reboot                = 120,
  Boolean $verbose_logging                  = false,
) {
  $base_dir = '/usr/share/cis_security_hardening'

  class { 'cis_security_hardening::services':
    time_until_reboot => $time_until_reboot,
  }

  class { 'cis_security_hardening::sticky_world_writable_cron':
    dirs_to_exclude => $exclude_dirs_sticky_ww,
    filename        => "${base_dir}/data/world-writable-files.txt",
    script          => "${base_dir}/bin/sticy-world-writable.sh",
  }

  class { 'cis_security_hardening::auditd_cron':
    dirs_to_include => $auditd_dirs_to_include,
    output_file     => "${base_dir}/data/auditd_priv_cmds.txt",
    script          => "${base_dir}/bin/auditd_priv_cmds.sh",
  }

  class { 'cis_security_hardening::config':
    base_dir               => $base_dir,
    update_postrun_command => $update_postrun_command,
    fact_upload_command    => $fact_upload_command,
  }

  $os = fact('operatingsystem') ? {
    undef   => 'unknown',
    default => fact('operatingsystem').downcase()
  }

  $os_maj = fact('operatingsystemmajrelease') ? {
    undef   => 'unknown',
    default => fact('operatingsystemmajrelease'),
  }
  $os_vers = $os ? {
    'ubuntu' => split($os_maj, '[.]')[0],
    default  => $os_maj,
  }

  $key = "cis_security_hardening::benchmark::${os}::${os_vers}"
  $benchmark = lookup($key, undef, undef, {})

  if has_key($benchmark, 'bundles') {
    $benchmark['bundles'].each |$bundle, $bundle_data| {
      $level1 = has_key($bundle_data, 'level1') ? {
        true  => $bundle_data['level1'],
        false => [],
      }

      $level2 = has_key($bundle_data, 'level2') ? {
        true  => $bundle_data['level2'],
        false => [],
      }

      $stig = has_key($bundle_data, 'stig') ? {
        true => $bundle_data['stig'],
        false => [],
      }

      $rules = $level ? {
        '1' => $level1,
        '2' => concat($level1, $level2),
        'stig' => concat($level1, $level2, $stig)
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

        if $verbose_logging {
          echo { "Applying ${class}":
            message  => "Applying ${class}",
            loglevel => 'info',
            withpath => false,
          }
        }

        include $class
      }
    }
  } else {
    echo { 'no bundles':
      message  => "No bundles found, enforcing nothing. (key = ${key})",
      loglevel => 'warning',
      withpath => false,
    }
  }
}

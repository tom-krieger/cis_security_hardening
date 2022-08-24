# @summary 
#    Configure the module
#
# Create files, install scripts and cron jobs
#
# @param update_postrun_command
#    Update Puppet agent's postrun command.
# @param base_dir
#    Directory where all files go to.
# @param fact_upload_command
#    Command to use for fact upload.
#
# @example
#   include cis_security_hardening::config
class cis_security_hardening::config (
  Boolean $update_postrun_command,
  Stdlib::Absolutepath $base_dir,
  Stdlib::Absolutepath $fact_upload_command,
) {
  file { $base_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { "${base_dir}/logs":
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { "${base_dir}/data":
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { "${base_dir}/bin":
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  file { "${base_dir}/bin/fact_upload.sh":
    ensure  => file,
    content => epp('cis_security_hardening/fact_upload.sh.epp', {
    }),
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
  }

  if $update_postrun_command {
    if fact('cis_security_hardening.puppet_agent_postrun') != "postrun_command = ${fact_upload_command}" {
      file_line { 'append postrun command agent':
        path               => '/etc/puppetlabs/puppet/puppet.conf',
        after              => '[agent]',
        match              => 'postrun_command\s*=',
        line               => "postrun_command = ${fact_upload_command}",
        append_on_no_match => true,
      }

      file_line { 'append postrun command main':
        path               => '/etc/puppetlabs/puppet/puppet.conf',
        after              => 'certname\s*=.*',
        match              => 'postrun_command\s*=',
        line               => "postrun_command = ${fact_upload_command}",
        append_on_no_match => true,
      }
    }
  }
}

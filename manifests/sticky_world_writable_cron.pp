# @summary
#   Create a cron job for the search for world writable directories with sticky bit set.
#
# @param ensure
#   Whether the cron job should be present or absent.
# @param dirs_to_exclude
#    Array of directories to exclude from search.
# @param filename
#    The file to write data to
# @param script
#    The script to run
#
# @example
#   include cis_security_hardening::sticky_world_writable_cron
class cis_security_hardening::sticky_world_writable_cron (
  Enum['present', 'absent'] $ensure    = 'present',
  Array $dirs_to_exclude               = [],
  Stdlib::Absolutepath $filename       = '/usr/share/cis_security_hardening/data/world-writable-files.txt',
  Stdlib::Absolutepath $script         = '/usr/share/cis_security_hardening/bin/sticy-world-writable.sh',
) {
  file { $script:
    ensure  => stdlib::ensure($ensure, file),
    content => epp("${module_name}/sticky-world-writeable.epp",
      {
        filename        => $filename,
        dirs_to_exclude => $dirs_to_exclude,
      },
    ),
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
  }

  $min = fqdn_rand(60, 'ah  ue65^b  gdf^zrbzcê2zf^b w')

  file { '/etc/cron.d/sticky-world-writebale.cron':
    ensure => absent,
  }

  file { '/etc/cron.d/sticky-world-writebale':
    ensure  => stdlib::ensure($ensure, file),
    content => epp("${module_name}/sticky-world-writeable.cron.epp",
      {
        min    => $min,
        script => $script,
      },
    ),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }
}

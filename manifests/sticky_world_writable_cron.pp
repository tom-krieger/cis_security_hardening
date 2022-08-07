# @summary 
#    Create cron job for searching world writable dir3ctories with sticky bit
#
# Create a cron ob for the search for world writable directories with sticky bit set.
#
# @param dirs_to_exclude
#    Array of directories to exclude from search.
#
# @param filename
#    The file to write data to
#
# @param script
#    The script to run
#
# @example
#   include cis_security_hardening::sticky_world_writable_cron
class cis_security_hardening::sticky_world_writable_cron (
  Array $dirs_to_exclude = [],
  String $filename       = '/usr/share/cis_security_hardening/data/world-writable-files.txt',
  String $script         = '/usr/share/cis_security_hardening/bin/sticy-world-writable.sh',
) {
  file { $script:
    ensure  => file,
    content => epp('cis_security_hardening/sticky-world-writeable.epp', {
        filename        => $filename,
        dirs_to_exclude => $dirs_to_exclude,
    }),
    owner   => 'root',
    group   => 'root',
    mode    => '0700',
  }

  $min = fqdn_rand(60, 'ah  ue65^b  gdf^zrbzcê2zf^b w')

  file { '/etc/cron.d/sticky-world-writebale.cron':
    ensure  => file,
    content => epp('cis_security_hardening/sticky-world-writeable.cron.epp', {
        min    => $min,
        script => $script,
    }),
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
  }
}

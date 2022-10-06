# @summary
#    Ensure prelink is disabled 
#
# prelinkis a program that modifies ELF shared libraries and ELF dynamically linked binaries 
# in such a way that the time needed for the dynamic linker to perform relocations at startup 
# significantly decreases.
#
# Rationale:
# The prelinking feature can interfere with the operation of AIDE, because it changes binaries. 
# Prelinking can also increase the vulnerability of the system if a malicious user is able to 
# compromise a common library such as libc.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::disable_prelink':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_prelink (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['osfamily'].downcase() ? {
      'suse'   => 'absent',
      default => 'purged',
    }

    ensure_packages(['prelink'], {
        ensure => $ensure,
    })

    exec { 'reset prelink':
      command => 'prelink -ua',
      path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      onlyif  => 'test -f /sbin/prelink',
      before  => Package['prelink'],
    }
  }
}

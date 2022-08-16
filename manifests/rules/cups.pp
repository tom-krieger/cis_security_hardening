# @summary 
#    Ensure CUPS is not enabled (Automated)
#
# The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. 
# A system running CUPS can also accept print jobs from remote systems and print them to local printers. 
# It also provides a web based remote administration capability.
#
# Rationale:
# If the system does not need to print jobs or accept print jobs from other systems, it is recommended 
# that CUPS be disabled to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::cups':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::cups (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure =  $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    case $facts['os']['name'].downcase() {
      'ubuntu', 'sles': {
        ensure_packages(['cups'], {
            ensure => $ensure,
        })
      }
      'rocky': {
        ensure_packages(['cups'], {
            ensure => $ensure,
        })
      }
      default: {
        ensure_resource('service', ['cups'], {
            ensure => 'stopped',
            enable => false,
        })
      }
    }
  }
}

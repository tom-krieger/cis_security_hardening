# @summary 
#    Ensure DNS Server is not installed 
#
# The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for 
# computers, services and other resources connected to a network.
#
# Rationale:
# Unless a system is specifically designated to act as a DNS server, it is recommended that the package 
# be removed to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::bind':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::bind (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['family'].downcase() {
      'suse': {
        $pkgs = ['bind']
        $ensure = 'absent'
      }
      default: {
        if $facts['os']['name'].downcase() == 'ubuntu' {
          $pkgs = ['bind9']
        } else {
          $pkgs = ['bind']
        }
        $ensure = 'purged'
      }
    }

    ensure_packages($pkgs, {
        ensure => $ensure,
    })
  }
}

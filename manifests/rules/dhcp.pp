# @summary 
#    Ensure DHCP Server is not enabled 
#
# The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.
#
# Rationale:
# Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be disabled 
# to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dhcp':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::dhcp (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['operatingsystem'].downcase() {
      'ubuntu': {
        ensure_packages(['isc-dhcp-server'], {
            ensure => purged,
        })
      }
      'debian': {
        ensure_resource('service', 'isc-dhcp-server', {
            ensure => 'stopped',
            enable => false
        })
        ensure_resource('service', 'isc-dhcp-server6', {
            ensure => 'stopped',
            enable => false
        })
      }
      'sles': {
        ensure_packages(['dhcp'], {
            ensure => absent,
        })
      }
      default: {
        ensure_resource('service' ,['dhcpd'], {
            ensure => 'stopped',
            enable => false
        })
      }
    }
  }
}

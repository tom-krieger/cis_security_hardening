# @summary 
#    Ensure wireless interfaces are disabled (Not Scored)
#
# Wireless networking is used when wired networks are unavailable. Ubuntu contains a wireless tool kit 
# to allow system administrators to configure and use wireless networks.
#
# Rationale:
# If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @example
#   class { 'cis_security_hardening::rules::disable_wireless':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::disable_wireless (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['osfamily'].downcase() {
      'redhat': {
        $pkg = 'NetworkManager'
      }
      'debian': {
        $pkg = 'network-manager'
      }
      default: {
        $pkg = ''
      }
    }

    if !empty($pkg) {
      ensure_packages($pkg, {
          ensure => present,
      })
    }
    $wlan_status = fact('cis_security_hardening.wlan_status')
    $wlan_iface_count = fact('cis_security_hardening.wlan_interfaces_count')

    if $wlan_status  == 'enabled' {
      exec { 'switch radio off':
        command => 'nmcli radio all off',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
    } elsif $wlan_iface_count != undef and $wlan_iface_count != 0 {
      $wlan_ifaces = fact('cis_security_hardening.wlan_interfaces')
      if $wlan_ifaces != undef {
        $wlan_ifaces.each |$wlanif| {
          exec { "shutdown wlan interface ${wlanif}":
            command => "ip link set ${wlanif} down",
            path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
            onlyif  => "ip link show ${wlanif} | grep 'state UP'",
          }
        }
      }
    }
  }
}

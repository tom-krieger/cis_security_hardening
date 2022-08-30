# @summary 
#    Ensure network interfaces are assigned to appropriate zone 
#
# firewall zones define the trust level of network connections or interfaces.
#
# Rationale:
# A network interface not assigned to the appropriate zone can allow unexpected or undesired network 
# traffic to be accepted on the interface
#
# @param enforce
#    Enforce the rule
#
# @param zone_config
#    firewalld interface and zone config
#
# @example
#   class { 'cis_security_hardening::rules::firewalld_interface':
#       enforce => true,
#       zone_config => { 'public' => 'eth0' },
#   }
#
# @api public
class cis_security_hardening::rules::firewalld_interfaces (
  Boolean $enforce  = false,
  Hash $zone_config = {},
) {
  if $enforce {
    $zone_ifaces = fact('cis_security_hardening.firewalld.zone_iface') == undef ? {
      true => {},
      default => fact('cis_security_hardening.firewalld.zone_iface'),
    }

    $zone_config.each |$zone, $iface| {
      $zone_iface = fact("cis_security_hardening.firewalld.zone_iface.${zone}")

      if $zone_iface != undef and $zone_iface != $iface {
        exec { 'firewalld change zone interface':
          command => "firewall-cmd --zone=${zone} --change-interface=${iface}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  }
}

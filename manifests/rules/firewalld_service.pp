# @summary 
#    Ensure firewalld service is enabled and running 
#
# Ensure that the firewalld service is enabled to protect your system
#
# Rationale:
# firewalld (Dynamic Firewall Manager) tool provides a dynamically managed firewall. The tool enables network/firewall 
# zones to define the trust level of network connections and/or interfaces. It has support both for IPv4 and IPv6 firewall 
# settings. Also, it supports Ethernet bridges and allow you to separate between runtime and permanent configuration options. 
# Finally, it supports an interface for services or applications to add firewall rules directly
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::firewalld_service':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::firewalld_service (
  Boolean $enforce = false,
) {
  if $enforce {
    if  (!defined(Service['firewalld'])) and
    (!defined(Class['firewall'])) {
      ensure_resource('service', ['firewalld'], {
          ensure => running,
          enable => true,
      })
    }
  }
}

# @summary 
#    Ensure ufw service is enabled 
#
# Uncomplicated Firewall (ufw) is a frontend for iptables. ufw provides a framework for managing netfilter, 
# as well as a command-line and available graphical user interface for manipulating the firewall.
#
# Ensure that the ufw service is enabled to protect your system.
#
# Rationale:
# The ufw service must be enabled and running in order for ufw to protect the system
#
# @param enforce
#    Enforce the rule or just test and log
#
# @example
#   class cis_security_hardening::rules::ufw_service {
#       log_level => 'info',
#   }
#
# @api private
class cis_security_hardening::rules::ufw_service (
  Boolean $enforce = false,
) {
  if($enforce) {
    if(!defined(Service['ufw'])) {
      ensure_resource('service', ['ufw'], {
          ensure => running,
          enable => true,
      })
    }
    exec { 'enable-ufw':
      command => 'ufw --force enable',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      unless  => 'test -z "$(ufw status | grep \"Status: inactive\")"',
    }
  }
}

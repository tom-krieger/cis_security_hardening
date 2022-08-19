# @summary 
#    Save iptables rules
#
# Save iptables rules.
#
# @example
#   include cis_security_hardening::rules::iptables_save
#
# @api private
class cis_security_hardening::rules::iptables_save {
  if $facts['operatingsystem'].downcase() == 'rocky' {
    exec { 'save iptables rules':
      command => 'service iptables save',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    }
  }
}

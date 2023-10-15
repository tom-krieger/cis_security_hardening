# @summary 
#    Ensure IPv6 firewall rules exist for all open ports 
#
# Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
#
# Rationale:
# Without a firewall rule configured for open ports default firewall policy will drop all packets to 
# these ports.
#
# Notes:
# * Changing firewall settings while connected over network can result in being locked out of the system.
# * The remediation command opens up the port to traffic from all sources. Consult iptables documentation 
#   and set any restrictions in compliance with site policy.
#
# @param enforce
#    Enforce the rule
#
# @param firewall_rules
#    Hash with al firewall rules
#
# @example
#   class { 'ccis_security_hardening::rules::ip6tables_open_ports':
#       enforce => true,
#       firewall_rules => {},
#   }
#
# @api private
class cis_security_hardening::rules::ip6tables_open_ports (
  Boolean $enforce     = false,
  Hash $firewall_rules = {},
) {
  if  $enforce and fact('network6') != undef {
    if(empty($firewall_rules)) {
      $rule10 = fact('cis_security_hardening.ip6tables.policy').filter |$rule, $data| {
        $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and $data['dpt'] == '22' and
        $data['state'] == 'NEW' and $data['target'] == 'ACCEPT'
      }
      if ($rule10.empty) {
        firewall { '010-6 open ssh port inbound':
          chain    => 'INPUT',
          proto    => 'tcp',
          dport    => 22,
          state    => 'NEW',
          jump     => 'ACCEPT',
          protocol => 'ip6tables',
        }
      }
    } else {
      $firewall_rules.each | String $rulename, Hash $data | {
        firewall { $rulename:
          * => $data,
        }
      }
    }
  }
}

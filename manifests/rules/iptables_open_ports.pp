# @summary 
#    Ensure firewall rules exist for all open ports (Automated)
#
# Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
#
# Rationale:
# Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
#
# @param enforce
#    Enforce the rule
#
# @param firewall_rules
#    Additional firewall rules to setup
#
# @example
#   class { 'cis_security_hardening::rules::iptables_open_ports':
#       enforce => true,
#       firewall_rules => {},
#   }
#
# @api private
class cis_security_hardening::rules::iptables_open_ports (
  Boolean $enforce     = false,
  Hash $firewall_rules = {},
) {
  if $enforce {
    if(empty($firewall_rules)) {
      $policy = fact('cis_security_hardening.iptables.policy')
      if  $policy != undef {
        $rule10 = $policy.filter |$rule, $data| {
          $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and $data['dpt'] == '22' and
          $data['state'] == 'NEW' and $data['target'] == 'ACCEPT'
        }
      }

      if ($rule10.empty) {
        firewall { '010 open ssh port inbound':
          chain  => 'INPUT',
          proto  => 'tcp',
          dport  => 22,
          state  => 'NEW',
          action => 'accept',
          notify => Class['cis_security_hardening::rules::iptables_save'],
        }
      }
    } else {
      $firewall_rules.each | String $rulename, Hash $data | {
        firewall { $rulename:
          *      => $data,
          notify => Class['cis_security_hardening::rules::iptables_save'],
        }
      }
    }
  }
}

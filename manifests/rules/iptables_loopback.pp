# @summary 
#     Ensure loopback traffic is configured (Automated)
#
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the 
# loopback network (127.0.0.0/8).
#
# Rationale:
# Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The 
# loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces 
# should ignore traffic on this network as an anti-spoofing measure.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::iptables_loopback':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::iptables_loopback (
  Boolean $enforce = false,
) {
  if $enforce {
    firewall { '001 accept all incoming traffic to local interface':
      chain   => 'INPUT',
      proto   => 'all',
      iniface => 'lo',
      action  => 'accept',
    }
    firewall { '002 accept all outgoing traffic to local interface':
      chain    => 'OUTPUT',
      proto    => 'all',
      outiface => 'lo',
      action   => 'accept',
    }

    firewall { '003 drop all traffic to lo 127.0.0.1/8':
      chain  => 'INPUT',
      proto  => 'all',
      source => '127.0.0.1/8',
      action => 'drop',
    }
  }
}

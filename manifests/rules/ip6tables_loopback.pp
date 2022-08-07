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
#   class { 'cis_security_hardening::rules::ip6tables_loopback':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ip6tables_loopback (
  Boolean $enforce = false,
) {
  if  $enforce and
  fact('network6') != undef {
    firewall { '001-6 accept all incoming traffic to local interface':
      chain    => 'INPUT',
      proto    => 'all',
      iniface  => 'lo',
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '002-6 accept all outgoing traffic to local interface':
      chain    => 'OUTPUT',
      proto    => 'all',
      outiface => 'lo',
      action   => 'accept',
      provider => 'ip6tables',
    }

    firewall { '003-6 drop all traffic to lo ::1':
      chain    => 'INPUT',
      proto    => 'all',
      source   => '::1',
      action   => 'drop',
      provider => 'ip6tables',
    }
  }
}

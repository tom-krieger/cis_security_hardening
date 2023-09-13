# @summary 
#    Ensure outbound and established connections are configured 
#
# Configure the firewall rules for new outbound, and established connections.
#
# Rationale:
# If rules are not in place for new outbound, and established connections all packets will be dropped 
# by the default policy preventing network usage.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::iptables_outbound_established':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::iptables_outbound_established (
  Boolean $enforce = false,
) {
  if $enforce {
    firewall { '004 accept outbound tcp state new, established':
      chain  => 'OUTPUT',
      proto  => 'tcp',
      state  => ['NEW', 'ESTABLISHED'],
      jump => 'ACCEPT',
      notify => Exec['save iptables rules'],
    }
    firewall { '005 accept outbound udp state new, established':
      chain  => 'OUTPUT',
      proto  => 'udp',
      state  => ['NEW', 'ESTABLISHED'],
      jump => 'ACCEPT',
      notify => Exec['save iptables rules'],
    }
    firewall { '006 accept outbound icmp state new, established':
      chain  => 'OUTPUT',
      proto  => 'icmp',
      state  => ['NEW', 'ESTABLISHED'],
      jump => 'ACCEPT',
      notify => Exec['save iptables rules'],
    }
    firewall { '007 accept inbound tcp state established':
      chain  => 'INPUT',
      proto  => 'tcp',
      state  => 'ESTABLISHED',
      jump => 'ACCEPT',
      notify => Exec['save iptables rules'],
    }
    firewall { '008 accept inbound udp state established':
      chain  => 'INPUT',
      proto  => 'udp',
      state  => 'ESTABLISHED',
      jump => 'ACCEPT',
      notify => Exec['save iptables rules'],
    }
    firewall { '009 accept inbound icmp state established':
      chain  => 'INPUT',
      proto  => 'icmp',
      state  => 'ESTABLISHED',
      jump => 'ACCEPT',
      notify => Exec['save iptables rules'],
    }
  }
}

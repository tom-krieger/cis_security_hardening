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
#   class { 'cis_security_hardening::rules::ip6tables_outbound_established':
#       enforce => true, 
#   }
#
# @api private
class cis_security_hardening::rules::ip6tables_outbound_established (
  Boolean $enforce = false,
) {
  if  $enforce and fact('network6') != undef {
    firewall { '004-6 accept outbound tcp state new, established':
      chain    => 'OUTPUT',
      proto    => 'tcp',
      state    => ['NEW', 'ESTABLISHED'],
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '005-6 accept outbound udp state new, established':
      chain    => 'OUTPUT',
      proto    => 'udp',
      state    => ['NEW', 'ESTABLISHED'],
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '006-6 accept outbound icmp state new, established':
      chain    => 'OUTPUT',
      proto    => 'icmp',
      state    => ['NEW', 'ESTABLISHED'],
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '007-6 accept inbound tcp state established':
      chain    => 'INPUT',
      proto    => 'tcp',
      state    => 'ESTABLISHED',
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '008-6 accept inbound udp state established':
      chain    => 'INPUT',
      proto    => 'udp',
      state    => 'ESTABLISHED',
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '009-6 accept inbound icmp state established':
      chain    => 'INPUT',
      proto    => 'icmp',
      state    => 'ESTABLISHED',
      action   => 'accept',
      provider => 'ip6tables',
    }
  }
}

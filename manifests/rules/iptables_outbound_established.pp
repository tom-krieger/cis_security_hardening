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
    include cis_security_hardening::rules::iptables_save
    firewall { '004 accept outbound tcp state new, established':
      chain  => 'OUTPUT',
      proto  => 'tcp',
      state  => ['NEW', 'ESTABLISHED'],
      action => 'accept',
      notify => Class['cis_security_hardening::rules::iptables_save'],
    }
    firewall { '005 accept outbound udp state new, established':
      chain  => 'OUTPUT',
      proto  => 'udp',
      state  => ['NEW', 'ESTABLISHED'],
      action => 'accept',
      notify => Class['cis_security_hardening::rules::iptables_save'],
    }
    firewall { '006 accept outbound icmp state new, established':
      chain  => 'OUTPUT',
      proto  => 'icmp',
      state  => ['NEW', 'ESTABLISHED'],
      action => 'accept',
      notify => Class['cis_security_hardening::rules::iptables_save'],
    }
    firewall { '007 accept inbound tcp state established':
      chain  => 'INPUT',
      proto  => 'tcp',
      state  => 'ESTABLISHED',
      action => 'accept',
      notify => Class['cis_security_hardening::rules::iptables_save'],
    }
    firewall { '008 accept inbound udp state established':
      chain  => 'INPUT',
      proto  => 'udp',
      state  => 'ESTABLISHED',
      action => 'accept',
      notify => Class['cis_security_hardening::rules::iptables_save'],
    }
    firewall { '009 accept inbound icmp state established':
      chain  => 'INPUT',
      proto  => 'icmp',
      state  => 'ESTABLISHED',
      action => 'accept',
      notify => Class['cis_security_hardening::rules::iptables_save'],
    }
  }
}

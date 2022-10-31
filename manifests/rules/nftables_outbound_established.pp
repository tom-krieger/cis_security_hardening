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
# @param table
#    nftable table to add rules
#
# @example
#   class { 'cis_security_hardening::rules::nftables_outbound_established':
#       enforce => true,
#       table => 'default',
#   }
#
# @api private
class cis_security_hardening::rules::nftables_outbound_established (
  Boolean $enforce  = false,
  String $table     = 'inet',
) {
  if $enforce {
    exec { 'add nftables rule for input tcp established':
      command => "nft add rule ${table} filter input ip protocol tcp ct state established accept", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip protocol tcp ct state established accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'add nftables rule for input udp established':
      command => "nft add rule ${table} filter input ip protocol udp ct state established accept", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip protocol udp ct state established accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'add nftables rule for input icmp established':
      command => "nft add rule ${table} filter input ip protocol icmp ct state established accept", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip protocol icmp ct state established accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'add nftables rule for output tcp established':
      command => "nft add rule ${table} filter output ip protocol tcp ct state new,related,established accept", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip protocol tcp ct state established,related,new accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'add nftables rule for output udp established':
      command => "nft add rule ${table} filter output ip protocol udp ct state new,related,established accept", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip protocol udp ct state established,related,new accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'add nftables rule for output icmp established':
      command => "nft add rule ${table} filter output ip protocol icmp ct state new,related,established accept", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip protocol icmp ct state established,related,new accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }
  }
}

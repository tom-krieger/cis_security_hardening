# @summary 
#    Ensure loopback traffic is configured 
#
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic 
# to the loopback network.
#
# Rationale:
# Loopback traffic is generated between processes on machine and is typically critical to operation of 
# the system. The loopback interface is the only place that loopback network traffic should be seen, 
# all other interfaces should ignore traffic on this network as an anti- spoofing measure.
#
# @param enforce
#    Enforce the rule
#
# @param table
#    nftable table to add rules
#
# @example
#   class { 'cis_security_hardening::rules::nftables_loopback':
#       enforce => true,
#       table => 'default',
#   }
#
# @api private
class cis_security_hardening::rules::nftables_loopback (
  Boolean $enforce = false,
  String $table    = 'default',
) {
  if $enforce {
    exec { 'nftables add local interface':
      command => "nft add rule ${table} filter input iif lo accept", #lint:ignore:security_class_or_define_parameter_in_exec
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'iif \"lo\" accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'nftables add local network':
      command => "nft add rule ${table} filter input ip saddr 127.0.0.0/8 counter drop", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep -E 'ip\\s*saddr\\s*127.0.0.0/8\\s*counter\\s*packets.*drop')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'nftables ip6 traffic':
      command => "nft add rule ${table} filter input ip6 saddr ::1 counter drop", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip6 saddr ::1 counter packets')\"",
      notify  => Exec['dump nftables ruleset'],
    }
  }
}

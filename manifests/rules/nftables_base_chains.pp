# @summary 
#    Ensure base chains exist 
#
# Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an 
# entry point for packets from the networking stack, a regular chain may be used as jump target and is used 
# for better rule organization.
#
# Rationale:
# If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through 
# those chains will not be touched by nftables.
#
# @param enforce
#    Enforce the rule
#
# @param table
#    nftable table to add rules
#
# @example
#   class { 'cis_security_hardening::rules::nftables_base_chains':
#       enforce => true,
#       table => 'default',
#   }
#
# @api private
class cis_security_hardening::rules::nftables_base_chains (
  Boolean $enforce                                         = false,
  Cis_security_hardening::Nftables_address_families $table = 'inet',
) {
  if $enforce {
    exec { 'create base chain input':
      command => "nft create chain ${table} filter input { type filter hook input priority 0 \\; }", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft -n list ruleset ${table} | grep 'type filter hook input priority 0')\"",
      notify  => Exec['dump nftables ruleset'],
      require => Package['nftables'],
    }

    exec { 'create base chain forward':
      command => "nft create chain ${table} filter forward { type filter hook forward priority 0 \\; }", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft -n list ruleset ${table} | grep 'type filter hook forward priority 0')\"",
      notify  => Exec['dump nftables ruleset'],
      require => Package['nftables'],
    }

    exec { 'create base chain output':
      command => "nft create chain ${table} filter output { type filter hook output priority 0 \\; }", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft -n list ruleset ${table} | grep 'type filter hook output priority 0')\"",
      notify  => Exec['dump nftables ruleset'],
      require => Package['nftables'],
    }
  }
}

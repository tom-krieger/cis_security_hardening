# @summary 
#    Ensure a table exists 
#
# Tables hold chains. Each table only has one address family and only applies to packets of this family. 
# Tables can have one of five families.
#
# Rationale:
# nftables doesn't have any default tables. Without a table being build, nftables will not filter 
# network traffic.
#
# @param enforce
#    Enforce the rule
#
# @param nftables_default_table
#    Table to be created if none exists 
#
# @example
#   class  { 'cis_security_hardening::rules::nftables_table':
#       enforce => true,
#       nftables_default_table => 'inet',
#   }
#
# @api private
class cis_security_hardening::rules::nftables_table (
  Boolean $enforce                                                          = false,
  Cis_security_hardening::Nftables_address_families $nftables_default_table = 'inet',
) {
  if $enforce {
    $tables = fact('cis_security_hardening.nftables.tables')

    if(!($nftables_default_table in $tables)) {
      if(!defined(Package['nftables'])) {
        ensure_packages(['nftables'], {
            ensure => installed,
            before => Exec["create nft table ${nftables_default_table}"],
        })
      }

      exec { "create nft table ${nftables_default_table}":
        command => "nft create table ${nftables_default_table} filter", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        onlyif  => "test -z \"$(nft list ruleset | grep -E '^table ${nftables_default_table}')\"",
        notify  => Exec['dump nftables ruleset'],
        require => package['nftbles'],
      }
    }
  }
}

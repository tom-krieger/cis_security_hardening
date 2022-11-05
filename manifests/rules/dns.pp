# @summary
#    Ensure DNS is servers are configured
#
# The operating systems that are using DNS resolution, must have at least two name servers configured.
#
# Rationale:
# To provide availability for name resolution services, multiple redundant name servers are mandated. 
# A failure in name resolution could lead to the failure of security functions requiring name resolution, 
# which may include time synchronization, centralized authentication, and remote system logging.
#
# @param enforce
#    Enforce the rule.
# @param nsswitch_entry
#    The nsswitch.conf entry for dns.
# @param dns_servers
#    Array with dns servers to add into resolv.conf.
# @param dns_search
#    DNS search entries.
# @param dns_domain
#    The DNS domain.
#
# @example
#   class { 'cis_security_hardening::rules::dns':
#     enforce = true,
#   }
#
# @api private
class cis_security_hardening::rules::dns (
  Boolean $enforce             = false,
  String $nsswitch_entry       = 'files dns',
  Array $dns_servers           = [],
  Array $dns_search            = [],
  Optional[String] $dns_domain = undef,
) {
  if $enforce {
    file_line { 'nsswitch dns':
      ensure => present,
      path   => '/etc/nsswitch.conf',
      match  => '^hosts:',
      line   => "hosts:      ${nsswitch_entry}",
    }

    if(empty($dns_search)) {
      $real_dnssearch = ''
    } else {
      $real_dnssearch = join($dns_search, ' ')
    }

    if $facts['os']['selinux']['enabled'] {
      $file_data = {
        ensure  => file,
        content => epp('cis_security_hardening/rules/common/resolv.conf.epp', {
            dnsservers => $dns_servers,
            search     => $real_dnssearch,
            dnsdomain  => $dns_domain,
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        seltype => 'net_conf_t',
        notify  => Exec['resolv.conf immutable'],
      }
    } else {
      $file_data = {
        ensure  => file,
        content => epp('cis_security_hardening/rules/common/resolv.conf.epp', {
            dnsservers => $dns_servers,
            search     => $real_dnssearch,
            dnsdomain  => $dns_domain,
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        notify  => Exec['resolv.conf immutable'],
      }
    }

    file { '/etc/resolv.conf':
      * => $file_data,
    }

    exec { 'resolv.conf immutable':
      command => 'chattr +i /etc/resolv.conf',
      path    => ['/sbin','/usr/sbin','/bin','/usr/bin'],
      onlyif  => 'test -z "$(lsattr /etc/resolv.conf | cut -d \'-\' -f 5)"',
    }
  }
}

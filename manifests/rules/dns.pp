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
#
# @example
#   class { 'cis_security_hardening::rules::dns':
#     enforce = true,
#   }
#
# @api private
class cis_security_hardening::rules::dns (
  Boolean $enforce       = false,
  String $nsswitch_entry = 'files dns',
  Array $dns_servers     = [],
) {
  if $enforce {
    file_line { 'nsswitch dns':
      ensure => present,
      path   => '/etc/nsswitch.conf',
      match  => '^hosts:',
      line   => "hosts: ${nsswitch_entry}",
    }

    unless empty($dns_servers) {
      file { '/etc/resolv.conf':
        ensure  => file,
        content => epp('cis_security_hardening/rules/common/resolv.conf.epp', {
            dns_servers => $dns_servers,
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        notify  => Exec['resolv.conf immutable'],
      }

      exec { 'resolv.conf immutable':
        command     => 'chattr +i /etc/resolv.conf',
        path        => ['/sbin','/usr/sbin','/bin','/usr/bin'],
        refreshonly => true,
      }
    }
  }
}
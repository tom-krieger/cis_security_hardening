# @summary 
#    Ensure nftables rules are permanent 
#
# nftables is a subsystem of the Linux kernel providing filtering and classification of 
# network packets/datagrams/frames.
# The nftables service reads the /etc/sysconfig/nftables.conf file for a nftables file or 
# files to include in the nftables ruleset.
# A nftables ruleset containing the input, forward, and output base chains allow network 
# traffic to be filtered.
#
# Rationale:
# Changes made to nftables ruleset only affect the live system, you will also need to 
# configure the nftables ruleset to apply on boot.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::nftables_persistence':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nftables_persistence (
  Boolean $enforce = false,
) {
  require cis_security_hardening::rules::nftables_install
  if $enforce {
    if(!defined(File['/etc/sysconfig/nftables.conf'])) {
      file { '/etc/sysconfig/nftables.conf':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        require => Package['nftables'],
      }
    }
    file_line { 'add persistence file include':
      path               => '/etc/sysconfig/nftables.conf',
      line               => 'include "/etc/nftables/nftables.rules"',
      match              => 'include "/etc/nftables/nftables.rules"',
      append_on_no_match => true,
      require            => Package['nftables'],
    }

    exec { 'dump nftables ruleset':
      command     => 'nft list ruleset > /etc/nftables/nftables.rules',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
      require     => Package['nftables'],
    }
  }
}

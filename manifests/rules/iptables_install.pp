# @summary
#    Ensure iptables is installed 
#
# iptables allows configuration of the IPv4 tables in the linux kernel and the rules stored within them. 
# Most firewall configuration utilities operate as a front end to iptables.
#
# Rationale:
# iptables is required for firewall management and configuration.
#
# @param enforce
#    Enforce the rule
#
# @param configure_ip6tables
#    Flag if ip6tables should be configured
#
# @example
#   class { 'cis_security_hardening::rules::iptables_install':
#       enforce => true,
#       configure_ip6tables => false,
#   }
#
# @api private
class cis_security_hardening::rules::iptables_install (
  Boolean $enforce             = false,
  Boolean $configure_ip6tables = false,
) {
  if $enforce {
    if fact('network6') != undef {
      if  $configure_ip6tables == false {
        $params_ip6 = {
          ensure_v6 => 'stopped',
        }
      } else {
        $params_ip6 = {
          ensure_v6 => 'running',
        }
      }
    } else {
      $params_ip6 = {
        ensure_v6 => 'stopped',
      }
    }

    if $facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '20' {
      ensure_packages(['iptables', 'iptables-persist'], {
          ensure => installed,
      })
    }

    if ($facts['os']['name'].downcase() == 'redhat' or $facts['os']['name'].downcase() == 'centos') and
    $facts['os']['release']['major'] > '7' {
      $params_rh = {
        service_name => ['iptables'],
        service_name_v6 => 'ip6tables',
        package_name => ['iptables-services'],
      }
    } else {
      $params_rh = {}
    }

    $params = merge($params_ip6, $params_rh)

    if(!defined(Class['firewall'])) {
      class { 'firewall':
        * => $params,
      }
    }

    resources { 'firewall':
      purge => true,
    }

    case $facts['os']['name'].downcase() {
      'redhat', 'centos', 'almalinux', 'rocky': {
        if !defined(Package['nftables']) {
          ensure_packages(['nftables'], {
              ensure => purged,
          })
        }
        if ! defined(Service['nftables']) {
          ensure_resource('service', 'nftables', {
              enable => false,
              ensure => stopped,
          })
        }
        if !defined(Package['firewalld']) {
          ensure_packages(['firewalld'], {
              ensure => purged,
          })
        }
        if !defined(Service['firewalld']) {
          ensure_resource('service', 'firewalld', {
              enable => false,
              ensure => stopped,
          })
        }
      }
      'ubuntu', 'debian': {
        ensure_packages(['ufw', 'nftables'], {
            ensure => purged,
        })
      }
      'sles': {
        ensure_packages(['firewalld', 'nftables'], {
            ensure => absent,
        })
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

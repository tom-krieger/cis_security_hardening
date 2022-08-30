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
# @api public
class cis_security_hardening::rules::iptables_install (
  Boolean $enforce             = false,
  Boolean $configure_ip6tables = false,
) {
  if $enforce {
    if fact('network6') != undef {
      if  $configure_ip6tables == false {
        $params = {
          ensure_v6 => 'stopped',
        }
      } else {
        $params = {
          ensure_v6 => 'running',
        }
      }
    } else {
      $params = {
        ensure_v6 => 'stopped',
      }
    }

    if(!defined(Class['firewall'])) {
      class { 'firewall':
        * => $params,
      }
    }

    resources { 'firewall':
      purge => true,
    }

    case $facts['operatingsystem'].downcase() {
      'redhat', 'centos', 'almalinux', 'rocky': {
        if $facts['operatingsystemmajrelease'] < '8' {
          ensure_packages(['nftables'], {
              ensure => purged,
          })
          ensure_resource('service', 'nftables', {
              enable => false,
              ensure => stopped,
          })
        }
        ensure_packages(['firewalld'], {
            ensure => purged,
        })
        ensure_resource('service', 'firewalld', {
            enable => false,
            ensure => stopped,
        })
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

# @summary 
#    Ensure nftables is installed 
#
# nftables provides a new in-kernel packet classification framework that is based on a 
# network-specific Virtual Machine (VM) and a new nft userspace command line tool. nftables 
# reuses the existing Netfilter subsystems such as the existing hook infrastructure, the 
# connection tracking system, NAT, userspace queuing and logging subsystem.
#
# Notes:
#    * nftables is available in Linux kernel 3.13 and newer.
#    * Only one firewall utility should be installed and configured. 
#
# Rationale:
# nftables is a subsystem of the Linux kernel that can protect against threats originating 
# from within a corporate network to include malicious mobile code and poorly configured 
# software on a host.
#
# @param enforce
#    Enforce the rule
#
# @example cis_security_hardening::rules::nftables_installcis_security_hardening::rules::avahi {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nftables_install (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'sles': {
        $pkgs_remove = ['firewalld']
      }
      'centos': {
        $pkgs_remove = $facts['os']['release']['major'] ? {
          '7'     => ['firewalld', 'iptables-services'],
          default => ['firewalld'],
        }
      }
      default: {
        $pkgs_remove = ['firewalld', 'iptables-services']
      }
    }

    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    if !defined(Package['nftables']) {
      ensure_packages(['nftables'], {
          ensure => installed,
      })
    }

    ensure_packages($pkgs_remove, {
        ensure => $ensure,
    })

    if !defined(Service['iptables']) {
      ensure_resource('service', 'iptables', {
          enable => false,
          ensure => stopped,
      })
    }

    if !defined(Service['ip6tables']) {
      ensure_resource('service', 'ip6tables', {
          enable => false,
          ensure => stopped,
      })
    }

    if !defined(Service['nftables']) {
      ensure_resource('service', 'nftables', {
          enable => true,
          ensure => running,
      })
    }

    if $facts['os']['name'].downcase() == 'ubuntu' {
      ensure_packages(['ufw'], {
          ensure => $ensure,
      })
    }
  }
}

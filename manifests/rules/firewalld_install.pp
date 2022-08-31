# @summary 
#    Ensure a Firewall package is installed 
#
# firewalld is a firewall management tool for Linux operating systems. It provides firewall features by 
# acting as a front-end for the Linux kernel's netfilter framework via the iptables backend or provides 
# firewall features by acting as a front-end for the Linux kernel's netfilter framework via the nftables 
# utility.
#
# firewalld replaces iptables as the default firewall management tool. Use the firewalld utility to 
# configure a firewall for less complex firewalls. The utility is easy to use and covers the typical use 
# cases scenario. FirewallD supports both IPv4 and IPv6 networks and can administer separate firewall 
# zones with varying degrees of trust as defined in zone profiles.
#
# Note: Starting in v0.6.0, FirewallD added support for acting as a front-end for the Linux kernel's netfilter 
# framework via the nftables userspace utility, acting as an alternative to the nft command line program.
#
# Rationale:
# A firewall utility is required to configure the Linux kernel's netfilter framework via the iptables or nftables 
# back-end.
# The Linux kernel's netfilter framework host-based firewall can protect against threats originating from within 
# a corporate network to include malicious mobile code and poorly configured software on a host.
#
# Note: Only one firewall utility should be installed and configured. FirewallD is dependent on the iptables 
# package.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::firewalld_install':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::firewalld_install (
  Boolean $enforce = false,
) {
  if $enforce {
    $pkgs = $facts['operatingsystem'].downcase() ? {
      'sles'  => ['firewalld', 'iptables'],
      default => ['firewalld'],
    }

    $pkgs_remove = $facts['operatingsystem'].downcase() ? {
      'sles'  => ['nftables'],
      default => ['nftables', 'iptables-services'],
    }

    ensure_packages($pkgs, {
        ensure => installed,
    })

    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages($pkgs_remove, {
        ensure => $ensure,
    })

    ensure_resource('service', 'iptables', {
        enable => false,
        ensure => stopped,
    })

    ensure_resource('service', 'ip6tables', {
        enable => false,
        ensure => stopped,
    })

    ensure_resource('service', 'nftables', {
        enable => false,
        ensure => stopped,
    })
  }
}

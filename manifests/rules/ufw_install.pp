# @summary 
#    Ensure ufw is installed 
#
# The Uncomplicated Firewall (ufw) is a frontend for iptables and is particularly well-suited for 
# host-based firewalls. ufw provides a framework for managing netfilter, as well as a command-line 
# interface for manipulating the firewall
#
# Rationale:
# A firewall utility is required to configure the Linux kernel's netfilter framework via the 
# iptables or nftables back-end.
# 
# The Linux kernel's netfilter framework host-based firewall can protect against threats originating 
# from within a corporate network to include malicious mobile code and poorly configured software 
# on a host.
#
# Note: Only one firewall utility should be installed and configured. UFW is dependent on the 
# iptables package
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::ufw_install':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ufw_install (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['ufw'], {
        ensure => installed,
    })

    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['iptables-persistent'], {
        ensure => $ensure,
    })
  }
}

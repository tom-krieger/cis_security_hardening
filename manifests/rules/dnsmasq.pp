# @summary
#    Ensure dnsmasq is not installed (Automated)
#
# dnsmasq is a lightweight tool that provides DNS caching, DNS forwarding and DHCP (Dynamic Host Configuration Protocol) services.
#
# Rationale:
# Unless a system is specifically designated to act as a DNS caching, DNS forwarding and/or DHCP server, it is recommended that the 
# package be removed to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dovecot':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dnsmasq (
  Boolean $enforce = true,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'redhat': {
        ensure_packages(['dnsmasq'], {
            ensure => purged,
        })
      }
      'debian': {
        if $facts['os']['release']['major'] >= '12' {
          ensure_packages(['dnsmasq'], {
              ensure => purged,
          })
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

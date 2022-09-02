# @summary 
#    Ensure nftables service is enabled 
#
# The nftables service allows for the loading of nftables rulesets during boot, or starting of the nftables service.
#
# Rationale:
# The nftables service restores the nftables rules from the rules files referenced in the /etc/sysconfig/nftables.conf 
# file durring boot or the starting of the nftables service
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::nftables_service':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nftables_service (
  Boolean $enforce = false,
) {
  if $enforce {
    if(!defined(Service['nftables'])) {
      ensure_resource('service', ['nftables'], {
          ensure => running,
          enable => true,
      })
    }
  }
}

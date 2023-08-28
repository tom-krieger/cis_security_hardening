# @summary
#    Ensure journald service is enabled (Automated)
#
# Ensure that the systemd-journald service is enabled to allow capturing of logging events.
#
# Rationale:
# If the systemd-journald service is not enabled to start on boot, the system will not capture logging events.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   include 
# @example
#   class { 'cis_security_hardening::rules::systemd_journald_service':
#     enforce => true,
#   }
# 
# @api private
class cis_security_hardening::rules::systemd_journald_service (
  Boolean $enforce = false,
) {
  if $enforce {
    service { 'systemd-journald.service':
      ensure => running,
      enable => true,
    }
  }
}

# @summary 
#    Ensure auditd service is enabled .
#
# Turn on the auditd daemon to record system events.
#
# Rationale:
# The capturing of system events provides system administrators with information to allow them to 
# determine if unauthorized access to their system is occurring.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::sec_auditd_service':
#             enforce => true,
#   }
#
# @example
#   include cis_security_hardening::rules::auditd_service
#
# @api public
class cis_security_hardening::rules::auditd_service (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', ['auditd'], {
        ensure => running,
        enable => true,
    })
  }
}

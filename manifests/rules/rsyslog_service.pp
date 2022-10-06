# @summary 
#     Ensure rsyslog Service is enabled 
#
# Once the rsyslog package is installed it needs to be activated.
#
# Rationale:
# If the rsyslog service is not activated the system may default to the syslogd service or lack logging instead.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::rsyslog_service':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rsyslog_service (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', ['rsyslog'], {
        ensure  => running,
        enable  => true,
        require => Package['rsyslog'],
    })
  }
}

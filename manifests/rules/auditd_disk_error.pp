# @summary
#    Ensure the operating system takes the appropriate action when an audit processing failure occurs
#
# The operating system must take appropriate action when an audit processing failure occurs.
#
# Rationale:
# It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs 
# as required. Without this notification, the security personnel may be unaware of an impending failure of the audit 
# capability, and system operation may be adversely affected.
#
# Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit 
# storage capacity being reached or exceeded.
#
# This requirement applies to each audit data storage repository (i.e., distinct information system component where 
# audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage 
# repositories combined), or both.
#
# @param enforce
#    Enforce the rule.
# @param disk_error_action
#    The action to be taken on disk error.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_disk_error':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_disk_error (
  Boolean $enforce                                  = false,
  Enum['SYSLOG','SINGLE','HALT'] $disk_error_action = 'SYSLOG',
) {
  if $enforce {
    file_line { 'auditd_disk_error_action':
      line  => "disk_error_action = ${disk_error_action}",
      path  => '/etc/audit/auditd.conf',
      match => '^disk_error_action',
    }
  }
}

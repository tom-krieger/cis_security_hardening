# @summary
#    Ensure administrators are notified if an audit processing failure occurrs by modifying "/etc/aliases"
#
# The operating system's Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) 
# must have mail aliases to be notified of an audit processing failure.
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
#
# @example
#   class { 'cis_security_hardening::rules::postmaster_alias':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::postmaster_alias (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'postmaster_alias':
      ensure             => present,
      path               => '/etc/aliases',
      match              => '^postmaster:',
      line               => 'postmaster: root',
      append_on_no_match => true,
    }
  }
}

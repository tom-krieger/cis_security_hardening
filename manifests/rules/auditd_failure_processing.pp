# @summary 
#    Ensure the auditing processing failures are handled.
#
# The operating system must shut down upon audit processing failure, unless availability is an overriding concern. 
# If availability is a concern, the system must alert the designated staff in the event of an audit processing failure.
#
# Rationale:
# It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as 
# required. Without this notification, the security personnel may be unaware of an impending failure of the audit 
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
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_failure_processing':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_failure_processing (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'failure_processing':
      order   => '998',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-f 2',
    }
  }
}

# @summary 
#    Ensure audit_backlog_limit is sufficient 
#
# The backlog limit has a default setting of 64
#
# Rationale:
# during boot if audit=1, then the backlog will hold 64 records. If more that 64 records are 
# created during boot, auditd records will be lost and potential malicious activity could go 
# undetected.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param backlog_limit
#    Number of records in backlog
#
# @example
#   class { 'cis_security_hardening::rules::auditd_backlog_limit':
#             enforce => true,
#             backlog_limit => 8192,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_backlog_limit (
  Boolean $enforce       = false,
  Integer $backlog_limit = 8192,
) {
  if $enforce {
    kernel_parameter { 'audit_backlog_limit':
      ensure => present,
      value  => $backlog_limit,
    }
  }
}

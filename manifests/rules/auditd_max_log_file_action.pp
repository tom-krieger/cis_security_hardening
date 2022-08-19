# @summary 
#    Ensure audit logs are not automatically deleted 
#
# The max_log_file_action setting determines how to handle the audit log file reaching the max file 
# size. A value of keep_logs will rotate the logs but never delete old logs.
#
# Rationale:
# In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing 
# the audit history.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param max_log_file_action
#    Action to be taken of lofs reach max. size.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_max_log_file_action':
#             enforce => true,
#             max_log_file_action => 'keep_logs',
#   }
#
# @api private
class cis_security_hardening::rules::auditd_max_log_file_action (
  Boolean $enforce            = false,
  String $max_log_file_action = 'keep_logs',
) {
  if $enforce {
    file_line { 'auditd_max_log_file_action':
      line  => "max_log_file_action = ${$max_log_file_action}",
      path  => '/etc/audit/auditd.conf',
      match => '^max_log_file_action',
    }
  }
}

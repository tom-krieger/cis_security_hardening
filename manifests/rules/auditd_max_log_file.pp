# @summary 
#    Ensure audit log storage size is configured 
#
# Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be 
# rotated and a new log file will be started.
#
# Rationale:
# It is important that an appropriate size is determined for log files so that they do not impact the 
# system and audit data is not lost.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param max_log_size
#    Maximal log file size, defaults to 26 MB
#
# @example
#   class { 'cis_security_hardening::rules::auditd_max_log_file':
#             enforce => true,
#             max_log_size => 32,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_max_log_file (
  Boolean $enforce      = false,
  Integer $max_log_size = 16,
) {
  if $enforce {
    file_line { 'auditd_max_log_size':
      path  => '/etc/audit/auditd.conf',
      line  => "max_log_file = ${max_log_size}",
      match => '^max_log_file =',
    }
  }
}

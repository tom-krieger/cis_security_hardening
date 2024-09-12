# @summary
#    Ensure only authorized groups are assigned ownership of audit log files (Automated)
#
# Audit log files contain information about the system and system activity.
#
# Rationale:
# Access to audit records can reveal system and configuration data to attackers,
# potentially compromising its confidentiality.
#
# @param enforce
#    Enforce the rule.
# @param log_group
#    Group who owns the audit logfiles.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_log_config':
#    enforce => true,
#    log_group => 'root',
#   }
#
# @api private
class cis_security_hardening::rules::auditd_log_config (
  Boolean $enforce = false,
  String $log_group = 'root',
) {
  if $enforce {
    file { '/etc/audit/auditd.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0640',
    }

    file_line { 'auditd log group':
      ensure             => present,
      path               => '/etc/audit/auditd.conf',
      match              => '^log_group =',
      line               => "log_group = ${log_group}",
      append_on_no_match => true,
    }
  }
}

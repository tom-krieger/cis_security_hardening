# @summary 
#    Ensure audit log files are not read or write-accessible by unauthorized users
#
# The operating system must be configured so that audit log files are not read or write- accessible by unauthorized users.
#
# The operating system must be configured to permit only authorized users ownership of the audit log files.
#
# The operating system must permit only authorized groups ownership of the audit log files.
#
# Rationale:
# Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.
#
# Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit 
# operating system activity.
#
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028
#
# Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.
#
# Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit 
# operating system activity.
#
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059- GPOS-00029
#
# Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.
#
# Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit 
# operating system activity.
#
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059- GPOS-00029
#
# @param enforce
#    Enforce the rule.
# @param user
#    User who owns the audit logfiles.
# @param group
#    Group who owns the audit logfiles.
# @param mode
#    Access permissions for the auditd logfiles.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_log_perms':
#     enforce => true,
#     user => 'root',
#     group => 'root',
#     mode => '0600',
#   }
class cis_security_hardening::rules::auditd_log_perms (
  Boolean $enforce = false,
  String $user     = 'root',
  String $group    = 'root',
  String $mode     = '0600',
) {
  if $enforce {
    $logfiles = fact('cis_security_hardening.auditd.log_files')
    if $logfiles != undef {
      $logfiles.each |$logfile| {
        file { $logfile:
          ensure => file,
          owner  => $user,
          group  => $group,
          mode   => $mode,
        }
      }
    }
  }
}

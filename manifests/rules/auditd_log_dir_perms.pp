# @summary 
#    Ensure the audit log directory is 0750 or more restrictive
#
# The operating system must be configured so that the audit log directory is not write- accessible by unauthorized users.
#
# Rationale:
# If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially 
# malicious system activity is impossible to achieve.
#
# To ensure the veracity of audit information, the operating system must protect audit information from unauthorized 
# deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.
#
# Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully
# audit information system activity.
#
# @param enforce
#    Enforce the rule.
# @param user
#    The user to own the directory.
# @param group
#    The group to own the directory.
# @param mode
#    Directory access permissions.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_log_dir_perms':
#     enforce => true,
#     mode => '0750',
#   }
#
# @api private
class cis_security_hardening::rules::auditd_log_dir_perms (
  Boolean $enforce = false,
  String $user     = 'root',
  String $group    = 'root',
  String $mode     = '0750'
) {
  if $enforce {
    file { '/var/log/audit':
      ensure => directory,
      owner  => $user,
      group  => $group,
      mode   => $mode,
    }
  }
}

# @summary 
#    Ensure noexec option set on /var/log/audit partition
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries. 
#
# Rationale:
# Since the /var/log/audit filesystem is only intended for audit logs, set this option 
# to ensure that users cannot run executable binaries from /var/log/audit.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::var_log_audit_noexec':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_log_audit_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/var/log/audit') {
    cis_security_hardening::set_mount_options { '/var/log/audit-noexec':
      mountpoint   => '/var/log/audit',
      mountoptions => 'noexec',
    }
  }
}

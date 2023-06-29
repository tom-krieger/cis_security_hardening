# @summary 
#    Ensure nodev option set on /var/log/audit partition
#
# The nodev mount option specifies that the filesystem cannot contain special devices. 
# 
# Rationale:
# Since the /var/log/audit filesystem is not intended to support devices, set this option 
# to ensure that users cannot create a block or character special devices in /var/log/audit.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::var_log_audit_nosuid':
#     enforde => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_log_audit_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/var/log/audit') {
    cis_security_hardening::set_mount_options { '/var/log/audit-nodev':
      mountpoint   => '/var/log/audit',
      mountoptions => 'nodev',
    }
  }
}

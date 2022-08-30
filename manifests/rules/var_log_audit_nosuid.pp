# @summary 
#    Ensure nosuid option set on /var/log/audit partition
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files. 
#
# Rationale:
# Since the /var/log/audit filesystem is only intended for variable files such as logs, 
# set this option to ensure that users cannot create setuid files in /var/log/audit.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::var_log_audit_nosuid':
#     enforde => true,
#   }
#
# @api public
class cis_security_hardening::rules::var_log_audit_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var/log/audit') {
    cis_security_hardening::set_mount_options { '/var/log/audit-nosuid':
      mountpoint   => '/var/log/audit',
      mountoptions => 'nosuid',
    }
  }
}

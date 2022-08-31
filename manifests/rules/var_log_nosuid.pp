# @summary 
#    Ensure nosuid option set on /var/log partition
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files. 
# Rationale:
# Since the /var/log filesystem is only intended for log files, set this option to 
# ensure that users cannot create setuid files in /var/log.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::var_log_nosuid':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::var_log_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var/log') {
    cis_security_hardening::set_mount_options { '/var/log-nosuid':
      mountpoint   => '/var/log',
      mountoptions => 'nosuid',
    }
  }
}

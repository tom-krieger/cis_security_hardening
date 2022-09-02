# @summary 
#    Ensure nodev option set on /var/log partition
#
# The nodev mount option specifies that the filesystem cannot contain special devices . 
#
# Rationale:
# Since the /var/log filesystem is not intended to support devices, set this option to 
# ensure that users cannot create a block or character special devices in /var/log.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { #cis_security_hardening::rules::var_log_noexec':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_log_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var/log') {
    cis_security_hardening::set_mount_options { '/var/log-nodev':
      mountpoint   => '/var/log',
      mountoptions => 'nodev',
    }
  }
}

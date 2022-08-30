# @summary 
#    Ensure noexec option set on /var/log partition
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries. 
#
# Rationale:
# Since the /var/log filesystem is only intended for log files, set this option to ensure 
# that users cannot run executable binaries from /var/log.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { #cis_security_hardening::rules::var_log_noexec':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::var_log_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var/log') {
    cis_security_hardening::set_mount_options { '/var/log-noexec':
      mountpoint   => '/var/log',
      mountoptions => 'noexec',
    }
  }
}

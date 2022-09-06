# @summary
#    Ensure file systems that contain user home directories are mounted with the "noexec" option
#
# The operating system must prevent code from being executed on file systems that contain user home directories.
#
# Rationale:
# The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting 
# any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted 
# file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::home_noexec':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::home_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/home') {
    cis_security_hardening::set_mount_options { '/home-noexec':
      mountpoint   => '/home',
      mountoptions => 'noexec',
    }
  }
}

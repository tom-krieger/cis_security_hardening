# @summary 
#    Ensure the "/boot" directory is mounted with the "nosuid" option.
#
# The operating system must prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot" directory.
#
# Rationale:
# The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option 
# must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted 
# file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::boot_nosuid':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::boot_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/boot') {
    cis_security_hardening::set_mount_options { '/boot-nosuid':
      mountpoint   => '/boot',
      mountoptions => 'nosuid',
    }
  }
}

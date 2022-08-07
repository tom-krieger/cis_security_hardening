# @summary 
#    Ensure nosuid option set on /dev/shm partition (Automated)
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Setting this option on a file system prevents users from introducing privileged programs onto 
# the system and allowing non-root users to execute them.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm_nosuid':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-nosuid':
      mountpoint   => '/dev/shm',
      mountoptions => 'nosuid',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}

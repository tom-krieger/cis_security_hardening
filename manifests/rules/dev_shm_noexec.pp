# @summary 
#    Ensure noexec option set on /dev/shm partition (Automated)
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Setting this option on a file system prevents users from executing programs from shared memory. 
# This deters users from introducing potentially malicious software on the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm_noexec':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-noexec':
      mountpoint   => '/dev/shm',
      mountoptions => 'noexec',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}

# @summary 
#    Ensure nodev option set on /dev/shm partition (Automated)
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users 
# cannot attempt to create special devices in /dev/shm partitions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::dev_shm_nodev':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::dev_shm_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/dev/shm') {
    cis_security_hardening::set_mount_options { '/dev/shm-nodev':
      mountpoint   => '/dev/shm',
      mountoptions => 'nodev',
      require      => Class['cis_security_hardening::rules::dev_shm'],
    }
  }
}

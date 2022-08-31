# @summary 
#    Ensure nodev option set on /home partition
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the user partitions are not intended to support devices, set this option to ensure that users 
# cannot attempt to create block or character special devices.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::home_nodev':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::home_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/home') {
    cis_security_hardening::set_mount_options { '/home-nodev':
      mountpoint   => '/home',
      mountoptions => 'nodev',
    }
  }
}

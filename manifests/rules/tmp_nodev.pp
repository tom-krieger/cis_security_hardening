# @summary 
#    Ensure nodev option set on /tmp partition 
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the /tmp filesystem is not intended to support devices, set this option to ensure that 
# users cannot attempt to create block or character special devices in /tmp .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::tmp_nodev':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::tmp_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/tmp') {
    cis_security_hardening::set_mount_options { '/tmp-nodev':
      mountpoint   => '/tmp',
      mountoptions => 'nodev',
    }
  }
}

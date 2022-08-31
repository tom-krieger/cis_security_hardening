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
# @api public
class cis_security_hardening::rules::tmp_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) {
    $mps = fact('mountpoints') ? {
      undef   => {},
      default => fact('mountpoints')
    }
    if has_key($mps, '/tmp') and has_key($mps['/tmp'], 'device') and $mps['/tmp']['device'] != 'tmpfs' {
      cis_security_hardening::set_mount_options { '/tmp-nodev':
        mountpoint   => '/tmp',
        mountoptions => 'nodev',
      }
    }
  }
}

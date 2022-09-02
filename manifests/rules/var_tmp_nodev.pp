# @summary 
#    Ensure nodev option set on /var/tmp partition 
#
# The nodev mount option specifies that the filesystem cannot contain special devices.
#
# Rationale:
# Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that 
# users cannot attempt to create block or character special devices in /var/tmp .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::var_tmp_nodev':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_tmp_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var/tmp') {
    cis_security_hardening::set_mount_options { '/var/tmp-nodev':
      mountpoint   => '/var/tmp',
      mountoptions => 'nodev',
    }
  }
}

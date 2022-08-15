# @summary 
#    Ensure nodev option set on /var partition
#
# The nodev mount option specifies that the filesystem cannot contain special devices. 
#
# Rationale:
# Since the /var filesystem is not intended to support devices, set this option to ensure 
# that users cannot create a block or character special devices in /var.
#
# @param enforce
#    Enforcethe rule
#
# @example
#   class { 'cis_security_hardening::rules::var_nodev':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_nodev (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var') {
    cis_security_hardening::set_mount_options { '/var-nodev':
      mountpoint   => '/var',
      mountoptions => 'nodev',
    }
  }
}

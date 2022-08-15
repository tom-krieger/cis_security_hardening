# @summary 
#    Ensure nosuid option set on /home partition
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files. 
#
# Rationale:
# Since the /home filesystem is only intended for user file storage, set this option 
# to ensure that users cannot create setuid files in /home.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::home_nosuid':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::home_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/home') {
    cis_security_hardening::set_mount_options { '/home-nodev':
      mountpoint   => '/home',
      mountoptions => 'nodev',
    }
  }
}

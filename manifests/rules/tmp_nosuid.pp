# @summary 
#    Ensure nosuid option set on /tmp partition (Automated)    
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure 
# that users cannot create setuid files in /tmp .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::tmp_nosuid':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::tmp_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/tmp') {
    cis_security_hardening::set_mount_options { '/tmp-nosuid':
      mountpoint   => '/tmp',
      mountoptions => 'nosuid',
    }
  }
}

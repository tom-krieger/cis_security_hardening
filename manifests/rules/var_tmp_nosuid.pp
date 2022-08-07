# @summary 
#    Ensure nosuid option set on /var/tmp partition (Automated)
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure 
# that users cannot create setuid files in /var/tmp .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::var_tmp_nosuid':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_tmp_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var/tmp') {
    cis_security_hardening::set_mount_options { '/var/tmp-nosuid':
      mountpoint   => '/var/tmp',
      mountoptions => 'nosuid',
    }
  }
}

# @summary 
#    Ensure nosuid option set on /var partition
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files. 
#
# Rationale:
# Since the /var filesystem is only intended for variable files such as logs, set this 
# option to ensure that users cannot create setuid files in /var.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::var_nosuid':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_nosuid (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/var') {
    cis_security_hardening::set_mount_options { '/var-nosuid':
      mountpoint   => '/var',
      mountoptions => 'nosuid',
    }
  }
}

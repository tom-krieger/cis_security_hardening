# @summary 
#    Ensure noexec option set on /var partition
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries. 
#
# Rationale:
# Since the /var filesystem is only intended for variable files such as logs, set this option 
# to ensure that users cannot run executable binaries from /var.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::var_noexec':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::var_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/var') {
    cis_security_hardening::set_mount_options { '/var-noexec':
      mountpoint   => '/var',
      mountoptions => 'noexec',
    }
  }
}

# @summary 
#    Ensure noexec option set on /var/tmp partition 
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Since the /var/tmp filesystem is only intended for temporary file storage, set this option to 
# ensure that users cannot run executable binaries from /var/tmp .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::var_tmp_noexec':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::var_tmp_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) and cis_security_hardening::hash_key($facts['mountpoints'], '/var/tmp') {
    cis_security_hardening::set_mount_options { '/var/tmp-noexec':
      mountpoint   => '/var/tmp',
      mountoptions => 'noexec',
    }
  }
}

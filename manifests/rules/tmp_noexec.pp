# @summary 
#    Ensure noexec option set on /tmp partition 
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure 
# that users cannot run executable binaries from /tmp .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::tmp_noexec':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::tmp_noexec (
  Boolean $enforce = false,
) {
  if ($enforce) {
    $mps = fact('mountpoints') ? {
      undef   => {},
      default => fact('mountpoints')
    }
    if cis_security_hardening::hash_key($mps, '/tmp') and
    cis_security_hardening::hash_key($mps['/tmp'], 'device') and
    $mps['/tmp']['device'] != 'tmpfs' {
      cis_security_hardening::set_mount_options { '/tmp-noexec':
        mountpoint   => '/tmp',
        mountoptions => 'noexec',
      }
    }
  }
}

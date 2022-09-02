# @summary 
#    Ensure permissions on SSH public host key files are configured 
#
# An SSH public key is one of two files used in SSH public key authentication. In this authentication method, 
# a public key is a key that can be used for verifying digital signatures generated using a corresponding private 
# key. Only a public key that corresponds to a private key will be able to authenticate successfully.
#
# Rationale:
# If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_public_keys':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_public_keys (
  Boolean $enforce = false,
) {
  $pub_key_files = fact('cis_security_hardening.sshd.pub_key_files')

  if  $enforce and  $pub_key_files != undef {
    $pub_key_files.each |$file, $data| {
      if(!defined(File[$file])) {
        ensure_resource('file', $file, {
            owner => 'root',
            group => 'root',
            mode  => '0644',
        })
      }
    }
  }
}

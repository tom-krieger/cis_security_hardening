# @summary 
#    Ensure permissions on SSH private host key files are configured (Automated)
#
# An SSH private key is one of two files used in SSH public key authentication. In this authentication 
# method, The possession of the private key is proof of identity. Only a private key that corresponds 
# to a public key will be able to authenticate successfully. The private keys need to be stored and 
# handled carefully, and no copies of the private key should be distributed.
#
# Rationale:
# If an unauthorized user obtains the private SSH host key file, the host could be impersonated.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_private_keys':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_private_keys (
  Boolean $enforce = false,
) {
  $priv_key_files = fact('cis_security_hardening.sshd.priv_key_files')

  if $enforce and $priv_key_files != undef {
    $priv_key_files.each |$file, $data| {
      if(!defined(File[$file])) {
        ensure_resource('file', $file, {
            owner => 'root',
            group => 'root',
            mode  => '0600',
        })
      }
    }
  }
}

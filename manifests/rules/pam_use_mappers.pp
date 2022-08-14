# @summary 
#    Ensure authenticated identity is mapped to the user or group account for PKI-based authentication
#
# The operating system must map the authenticated identity to the user or group account for PKI-based 
# authentication.
#
# Rationale:
# Without mapping the certificate used to authenticate to the user account, the ability to determine 
# the identity of the individual user or group will not be available for forensic analysis.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::pam_use_mappers':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::pam_use_mappers (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'pam use mappers':
      ensure  => 'present',
      path    => '/etc/pam_pkcs11/pam_pkcs11.conf',
      line    => '  use_mappers = pwent',
      match   => 'use_mappers\s*=',
      require => File['/etc/pam_pkcs11/pam_pkcs11.conf']
    }
  }
}

# @summary 
#    Ensure certificates are validated by constructing a certification path to an accepted trust anchor
#
# The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a 
# certification path (which includes status information) to an accepted trust anchor.
#
# Rationale:
# Without path validation, an informed trust decision by the relying party cannot be made when 
# presented with any certificate not already explicitly trusted.
#
# A trust anchor is an authoritative entity represented via a public key and associated data. It 
# is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.
#
# When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; 
# it can be, for example, a Certification Authority (CA). A certification path starts with the 
# subject certificate and proceeds through a number of intermediate certificates up to a trusted 
# root certificate, typically issued by a trusted CA.
#
# This requirement verifies that a certification path to an accepted trust anchor is used for 
# certificate validation and that the path includes status information. Path validation is necessary 
# for a relying party to make an informed trust decision when presented with any certificate not already 
# explicitly trusted. Status information for certification paths includes certificate revocation lists or 
# online certificate status protocol responses. Validation of the certificate status information is out 
# of scope for this requirement.
#
# @param enforce
#    Enforce the rule.
# @param cert_policy
#    Comma seperated list of policies.
# @param pkcs11_config
#    Prepared config file to install. The file must be given in the 'puppet://modules/...' format.
#
# @example
#   class { 'cis_security_hardening::rules::pki_certs_validation':
#     enforce => tru,
#   }
#
# @api private
class cis_security_hardening::rules::pki_certs_validation (
  Boolean $enforce                = false,
  String $cert_policy             = 'ca,signature,ocsp_on;',
  Optional[String] $pkcs11_config = undef,
) {
  if $enforce {
    if $pkcs11_config == undef {

      $policy = fact('cis_security_hardening.pkcs11_config.policy')
      $match = "cert_policy\\s*=\\s*${policy};"
      $line = "    cert_policy = ${cert_policy}"

      file_line { 'pki certs validation':
        ensure   => present,
        path     => '/etc/pam_pkcs11/pam_pkcs11.conf',
        line     => $line,
        match    => $match,
        multiple => true,
      }

    } else {

      file { 'pkcs11_config prepared':
        ensure => file,
        source => $pkcs11_config,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }

    }
  }
}

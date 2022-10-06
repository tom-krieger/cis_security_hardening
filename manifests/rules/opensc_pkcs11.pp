# @summary 
#    Ensure the opensc-pcks11 is installed 
#
# The operating system must accept Personal Identity Verification (PIV) credentials.
#
# Rationale:
# The use of PIV credentials facilitates standardization and reduces the risk of unauthorized 
# access.
#
# DoD has mandated the use of the CAC to support identity management and personal authentication 
# for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making 
# he CAC a primary component of layered protection for national security systems.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::opensc_pkcs11':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::opensc_pkcs11 (
  Boolean $enforce = false,
) {
  if $enforce {
    $pkgs = $facts['operatingsystem'].downcase() ? {
      'redhat' => ['opensc'],
      default  => ['opensc-pkcs11'],
    }

    ensure_packages($pkgs, {
        ensure => present,
    })
  }
}

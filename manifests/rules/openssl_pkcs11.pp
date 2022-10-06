# @summary
#    Ensure the operating system has the packages required for multifactor authentication
#
# The operating system must have the packages required for multifactor authentication installed.
#
# Rationale:
# Using an authentication device, such as a DoD Common Access Card (CAC) or token that is separate from the information 
# system, ensures that even if the information system is compromised, credentials stored on the authentication device will 
# not be affected. Multifactor solutions that require devices separate from information systems gaining access include, for 
# example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. 
# Government Personal Identity Verification (PIV) card and the DoD CAC.
#
# A privileged account is defined as an information system account with authorizations of a privileged user.
#
# Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating 
# through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, 
# and wireless. This requirement only applies to components where this is specific to the function of the device or has the 
# concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of 
# configuring the device itself (management).
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::openssl_pkcs11':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::openssl_pkcs11 (
  Boolean $enforce = false
) {
  if $enforce {
    ensure_packages(['openssl-pkcs11'], {
        ensure => installed,
    })
  }
}

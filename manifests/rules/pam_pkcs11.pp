# @summary 
#    Ensure the libpam-pkcs11 package is installed
#
# The operating system must implement multifactor authentication for remote access to privileged 
# accounts in such a way that one of the factors is provided by a device separate from the system 
# gaining access.
#
# Rationale:
# Using an authentication device, such as a CAC or token that is separate from the information system, 
# ensures that even if the information system is compromised, that compromise will not affect credentials 
# stored on the authentication device.
#
# Multifactor solutions that require devices separate from information systems gaining access include, 
# for example, hardware tokens providing time-based or challenge-response authenticators and smart cards 
# such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
#
# A privileged account is defined as an information system account with authorizations of a privileged user.
#
# Remote access is access to DoD nonpublic information systems by an authorized user (or an information 
# system) communicating through an external, non-organization-controlled network. Remote access methods 
# include, for example, dial-up, broadband, and wireless.
#
# This requirement only applies to components where this is specific to the function of the device or 
# has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication 
# for the purpose of configuring the device itself (management).
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::pam_pkcs11':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::pam_pkcs11 (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['libpam-pkcs11'], {
      ensure => present,
    })
  }
}

# @summary
#    Ensure multifactor authentication for access to privileged accounts
#
# he operating system must implement multifactor authentication for access to privileged accounts via pluggable 
# authentication modules (PAM).
#
# Rationale:
# Using an authentication device, such as a CAC or token that is separate from the information system, ensures that 
# even if the information system is compromised, that compromise will not affect credentials stored on the authentication 
# device.
#
# Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware 
# tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity 
# Verification card and the DoD Common Access Card.
#
# A privileged account is defined as an information system account with authorizations of a privileged user.
#
# Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating 
# through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
#
# This requirement only applies to components where this is specific to the function of the device or has the concept of an 
# organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device 
# itself (management).
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sssd_mfa_services':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sssd_mfa_services (
  Boolean $enforce = false,
  String $services = 'nss, pam'
) {
  if $enforce {
    ensure_resource('file', '/etc/sssd/sssd.conf', {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
    })

    file_line { 'sssd mfa':
      ensure => present,
      path   => '/etc/sssd/sssd.conf',
      match  => '^services =',
      line   => "services = ${services}",
    }
  }
}

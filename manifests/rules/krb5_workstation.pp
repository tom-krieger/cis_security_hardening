# @summary 
#    Ensure the krb5-workstation package has not been installed on the system
#
# The krb5-workstation package must not be installed on the operating system. 
#
# Rationale:
# Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be 
# relied upon to provide confidentiality or integrity, and DoD data may be compromised.
#
# Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.
#
# Currently, Kerberos does not utilize FIPS 140-2 cryptography.
#
# FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication 
# that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::krb5_workstation':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::krb5_workstation (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['krb5-workstation'], {
        ensure => $ensure,
    })
  }
}

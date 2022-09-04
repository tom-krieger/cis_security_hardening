# @summary 
#    Ensure users must authenticate users using MFA via a graphical user logon
#
# The operating system must uniquely identify and must authenticate users using multifactor authentication 
# via a graphical user logon.
#
# Rationale:
# To assure accountability and prevent unauthenticated access, users must be identified and authenticated to 
# prevent potential misuse and compromise of the system.
#
# Multifactor solutions that require devices separate from information systems gaining access include, for example, 
# hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. 
# Government Personal Identity Verification card and the DoD Common Access Card.
#
# Satisfies: SRG-OS-000375-GPOS-00161,SRG-OS-000375-GPOS-00162
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::gdm_mfa':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_mfa (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/dconf/db/local.d/00-defaults':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file_line { 'mfa':
      ensure             => present,
      path               => '/etc/dconf/db/local.d/00-defaults',
      match              => '^enable-smartcard-authentication',
      line               => 'enable-smartcard-authentication=true',
      append_on_no_match => true,
      require            => File['/etc/dconf/db/local.d/00-defaults'],
    }
  }
}

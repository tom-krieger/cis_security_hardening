# @summary
#    Ensure multi-factor authentication is enable for users
#
# The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of 
# organizational users) using multi-factor authentication.
#
# Rationale:
# To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated 
# to prevent potential misuse and compromise of the system. Organizational users include organizational employees or individuals 
# the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting 
# on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: Accesses explicitly 
# identified and documented by the organization. Organizations document specific user actions that can be performed on the 
# information system without identification or authentication; and Accesses that occur through authorized use of group authenticators 
# without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared 
# privilege accounts) or for detailed accountability of individual activity.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::pam_mfa_redhat':
#     enfirce = true,
#   }
#
# @api private
class cis_security_hardening::rules::pam_mfa_redhat (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['dconf'], {
        ensure => installed,
    })

    exec { 'enable smartcard':
      command => 'authconfig --enablesmartcard --smartcardaction=0 --update',
      path    => ['bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(grep -E \"auth\s*\[success=done ignore=ignore default=die\] pam_pkcs11.so\" /etc/pam.d/smartcard-auth)"',
      require => Package['dconf'],
    }

    exec { 'enable required smartcard':
      command => 'authconfig --enablerequiresmartcard --update',
      path    => ['bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(grep -E \"auth\s*\[success=done ignore=ignore default=die\] pam_pkcs11.so\" /etc/pam.d/smartcard-auth)"',
      require => [Package['dconf'], Exec['enable smartcard']],
    }

    file_line { 'screensaver-lock':
      ensure             => present,
      path               => '/etc/pam_pkcs11/pkcs11_eventmgr.conf',
      match              => "#\s*action = \"/usr/sbin/gdm-safe-restart\", \"/etc/pkcs11/lockhelper.sh -deactivate\";",
      line               => "\t\taction = \"/usr/sbin/gdm-safe-restart\", \"/etc/pkcs11/lockhelper.sh -deactivate\", \"/usr/X11R6/bin/xscreensaveer-command -lock\";", #lint:ignore:140chars
      append_on_no_match => false,
      require            => Package['dconf'],
    }
  }
}

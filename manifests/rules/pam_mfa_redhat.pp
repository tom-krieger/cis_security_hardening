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

    file_line { 'authconfig-config-smartcard':
      ensure             => present,
      path               => '/etc/sysconfig/authconfig',
      match              => '^USESMARTCARD=',
      line               => 'USESMARTCARD=yes',
      append_on_no_match => true,
      notify             => Exec['authconfig-apply-changes'],
    }

    file_line { 'authconfig-config-force-smartcard':
      ensure             => present,
      path               => '/etc/sysconfig/authconfig',
      match              => '^FORCESMARTCARD=',
      line               => 'FORCESMARTCARD=yes',
      append_on_no_match => true,
      notify             => Exec['authconfig-apply-changes'],
    }

    Pam { 'pkcs11-system-auth':
      ensure           => present,
      service          => 'system-auth',
      type             => 'auth',
      control          => '[success=done ignore=ignore default=die]',
      control_is_param => true,
      module           => 'pam_pkcs11.so',
      arguments        => ['nodebug', 'wait_for_card'],
      position         => 'before *[type="auth" and module="pam_unix.so"]',
    }

    Pam { 'pkcs11-smartcard-auth-auth':
      ensure           => present,
      service          => 'smartcard-auth',
      type             => 'auth',
      control          => '[success=done ignore=ignore default=die]',
      control_is_param => true,
      module           => 'pam_pkcs11.so',
      arguments        => ['nodebug', 'wait_for_card'],
      position         => 'after *[type="auth" and module="pam_faillock.so"]',
    }

    Pam { 'pkcs11-smartcard-auth-password':
      ensure  => present,
      service => 'smartcard-auth',
      type    => 'password',
      control => 'required',
      module  => 'pam_pkcs11.so',
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

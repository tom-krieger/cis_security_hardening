# @summary 
#    Ensure password expiration is 365 days or less (Automated)
#
# The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. 
# It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 365 days.
#
# Rationale:
# The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online 
# brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an 
# attacker's window of opportunity.
#
# @param enforce
#    Enforce the rule
#
# @param max_pass_days
#    Password expires after days
#
# @example
#   class { 'cis_security_hardening::rules::passwd_expiration':
#       enforce => true,
#       max_pass_days => 50,
#   } 
#
# @api private
class cis_security_hardening::rules::passwd_expiration (
  Boolean $enforce       = false,
  Integer $max_pass_days = 90,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true  => '/usr/etc/login.defs',
      false => '/etc/login.defs',
    }
    file_line { 'password expiration policy':
      ensure => present,
      path   => $path,
      line   => "PASS_MAX_DAYS ${max_pass_days}",
      match  => '^#?PASS_MAX_DAYS',
    }

    $pw_data = fact('cis_security_hardening.pw_data')

    if $pw_data != undef {
      fact('cis_security_hardening.local_users').each |String $user, Hash $attributes| {
        if $attributes['max_days_between_password_change'] != $max_pass_days {
          exec { "chage --maxdays ${max_pass_days} ${user}":
            path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
        }
      }
    }
  }
}

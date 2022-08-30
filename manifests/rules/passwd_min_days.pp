# @summary 
#    Ensure minimum days between password changes is 7 or more 
#
# The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing 
# their password until a minimum number of days have passed since the last time the user changed their 
# password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.
#
# Rationale:
# By restricting the frequency of password changes, an administrator can prevent users from repeatedly 
# changing their password in an attempt to circumvent password reuse controls.
#
# @param enforce
#    Enforce the rule
#
# @param min_pass_days
#    Minimum days between password changes
#
# @example
#   class { 'cis_security_hardening::rules::passwd_min_days':
#       enforce => true,
#       min_pass_days => 7,
#   }
#
# @api public
class cis_security_hardening::rules::passwd_min_days (
  Boolean $enforce       = false,
  Integer $min_pass_days = 7,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true  => '/usr/etc/login.defs',
      false => '/etc/login.defs',
    }
    file_line { 'password min days password change':
      ensure => present,
      path   => $path,
      line   => "PASS_MIN_DAYS ${min_pass_days}",
      match  => '^#?PASS_MIN_DAYS',
    }

    $local_users = fact('cis_security_hardening.local_users')
    if  $local_users != undef {
      $local_users.each |String $user, Hash $attributes| {
        if
        $attributes['password_expires_days'] != 'never' and
        $attributes['min_days_between_password_change'] != $min_pass_days {
          exec { "chage --mindays ${min_pass_days} ${user}":
            path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
        }
      }
    }
  }
}

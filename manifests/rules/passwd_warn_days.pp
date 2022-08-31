# @summary 
#    Ensure password expiration warning days is 7 or more 
#
# The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their 
# password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE 
# parameter be set to 7 or more days.
# 
# Rationale:
# Providing an advance warning that a password will be expiring gives users time to think of a secure 
# password. Users caught unaware may choose a simple password or write it down where it may be discovered.
#
# @param enforce
#    Enforce the rule 
#
# @param warn_pass_days
#    Minimum dfays before a expiration warning is given.
#
# @example
#   class { 'cis_security_hardening::rules::passwd_warn_days':
#       enforce => true,
#       warn_pass_days => 7,
#   }
#
# @api public
class cis_security_hardening::rules::passwd_warn_days (
  Boolean $enforce        = false,
  Integer $warn_pass_days = 7,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true  => '/usr/etc/login.defs',
      false => '/etc/login.defs',
    }
    file_line { 'password warning days':
      ensure => present,
      path   => $path,
      line   => "PASS_WARN_AGE ${warn_pass_days}",
      match  => '^#?PASS_WARN_AGE',
    }

    $local_users = fact('cis_security_hardening.local_users')

    if  $local_users != undef {
      $local_users.each |String $user, Hash $attributes| {
        if $attributes['warn_days_between_password_change'] != $warn_pass_days {
          exec { "chage --warndays ${warn_pass_days} ${user}":
            path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
        }
      }
    }
  }
}

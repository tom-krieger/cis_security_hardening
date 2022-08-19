# @summary 
#    Ensure inactive password lock is 30 days or less 
#
# User accounts that have been inactive for over a given period of time can be automatically disabled. 
# It is recommended that accounts that are inactive for 30 days after password expiration be disabled.
# 
# Rationale:
# Inactive accounts pose a threat to system security since the users are not logging in to notice failed 
# login attempts or other anomalies.
#
# @param enforce
#    Enforce the rule
#
# @param inactive_pass_days
#    Days after an inactive account is locked
#
# @example
#   class { 'cis_security_hardening::rules::passwd_inactive_days':
#       enforce => true,
#       inactive_pass_days => 20,
#   }
#
# @api private 
class cis_security_hardening::rules::passwd_inactive_days (
  Boolean $enforce            = false,
  Integer $inactive_pass_days = 30,
) {
  if $enforce {
    $local_users = fact('cis_security_hardening.local_users')

    if  $local_users != undef {
      $local_users.each |String $user, Hash $attributes| {
        if (
          ($attributes['password_expires_days'] != 'never') and
          ($attributes['password_expires_days'] != 'password must be changed') and
          ($attributes['password_inactive_days'] != $inactive_pass_days)
        ) {
          exec { "chage --inactive ${inactive_pass_days} ${user}":
            path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
        }
      }

      $inactive = fact('cis_security_hardening.pw_data.inactive')
      if $inactive != undef and $inactive != $inactive_pass_days {
        exec { "useradd -D -f ${inactive_pass_days}":
          path => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  }
}

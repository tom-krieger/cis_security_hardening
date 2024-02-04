# @summary 
#    Ensure system accounts aresecured 
#
# There are a number of accounts provided with Red Hat 7 that are used to manage applications and are not 
# intended to provide an interactive shell.
#
# Rationale:
# It is important to make sure that accounts that are not being used by regular users are prevented from 
# being used to provide an interactive shell. By default Red Hat 7 sets the password field for these accounts 
# to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin . 
# This prevents the account from potentially being used to run any commands.
#
# @param enforce
#    Enforce the rule
#
# @param exclude
#   Shells to exclude.
#
# @example
#   class { 'cis_security_hardening::rules::shell_nologin':
#       enforce => true,
#       exclude => ['postgres'],
#   }
#
# @api private 
class cis_security_hardening::rules::shell_nologin (
  Boolean $enforce = false,
  Array $exclude   = [],
) {
  if $enforce {
    $no_shell_nologin = fact('cis_security_hardening.accounts.no_shell_nologin')
    if  $no_shell_nologin != undef and !empty($no_shell_nologin) {
      $no_shell_nologin.each | String $user | {
        if $user in $exclude {
          echo { "user ${user} excluded":
            message  => "user ${user} excluded",
            loglevel => 'info',
            withpath => false,
          }
        } else {
          exec { "nologin ${user}":
            command => "usermod -s /sbin/nologin ${user}",
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
        }
      }
    }
  }
}

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
#   Accounts to exclude.
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
    case $facts['os']['name'].downcase() {
      'debian': {
        $nologin = $facts['os']['release']['major'] ? {
          '12'    => '/usr/sbin/nologin',
          default => '/sbin/nologin',
        }
      }
      default: {
        $nologin = '/sbin/nologin'
      }
    }
    $no_shell_nologin = fact('cis_security_hardening.accounts.no_shell_nologin')
    if  $no_shell_nologin != undef and !empty($no_shell_nologin) {
      $no_shell_nologin.each | String $user | {
        unless $user in $exclude {
          exec { "nologin ${user}":
            command => "usermod -s ${nologin} ${user}",
            path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          }
        }
      }
    }
  }
}

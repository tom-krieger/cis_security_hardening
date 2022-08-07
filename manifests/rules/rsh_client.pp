# @summary 
#    Ensure rsh client is not installed (Automated)
#
# The rsh package contains the client commands for the rsh services.
#
# Rationale:
# These legacy clients contain numerous security exposures and have been replaced with the more 
# secure SSH package. Even if the server is removed, it is best to ensure the clients are also 
# removed to prevent users from inadvertently attempting to use these commands and therefore 
# exposing their credentials. Note that removing the rsh package removes the clients for rsh , 
# rcp and rlogin .
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::rsh_client':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rsh_client (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['operatingsystem'].downcase() == 'ubuntu' {
      # rsh-client is virtual and can not be removed as ssh package will be removed as well
      $pkg = 'rsh-client'
    } else {
      $pkg = 'rsh'
      $ensure = $facts['osfamily'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }
      ensure_packages($pkg, {
          ensure => $ensure,
      })
    }
  }
}

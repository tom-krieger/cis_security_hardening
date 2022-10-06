# @summary 
#    Ensure HTTP Proxy Server is not enabled 
#
# Squid is a standard proxy server used in many distributions and environments.
#
# Rationale:
# If there is no need for a proxy server, it is recommended that the squid proxy be disabled to 
# reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::squid':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::squid (
  Boolean $enforce = false,
) {
  if $enforce {
    if  $facts['operatingsystem'].downcase() == 'ubuntu' or
    $facts['operatingsystem'].downcase() == 'sles' {
      $ensure = $facts['osfamily'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }
      ensure_packages(['squid'], {
          ensure => $ensure,
      })
    } else {
      ensure_resource('service', ['squid'], {
          ensure => 'stopped',
          enable => false
      })
    }
  }
}

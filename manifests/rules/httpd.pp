# @summary 
#    Ensure HTTP server is not enabled 
#
# HTTP or web servers provide the ability to host web site content.
#
# Rationale:
# Unless there is a need to run the system as a web server, it is recommended that the service be 
# disabled to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::httpd':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::httpd (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'ubuntu', 'debian': {
        ensure_packages(['apache2'], {
            ensure => purged,
        })
      }
      'sles': {
        ensure_packages(['httpd'], {
            ensure => absent,
        })
      }
      'redhat': {
        if $facts['os']['release']['major'] >= '9' {
          ensure_packages(['nginx'], {
              ensure => purged,
          })
        }
        ensure_packages(['httpd'], {
            ensure => purged,
        })
      }
      default: {
        ensure_resource('service', ['httpd'], {
            ensure => 'stopped',
            enable => false
        })
      }
    }
  }
}

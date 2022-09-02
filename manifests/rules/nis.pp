# @summary 
#    Ensure NIS Server is not enabled 
#
# The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory 
# service protocol for distributing system configuration files. The NIS server is a collection of 
# programs that allow for the distribution of configuration files.
#
# Rationale:
# The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer 
# overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such 
# protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be 
# disabled and other, more secure services be used.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::nis {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nis (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['operatingsystem'].downcase() {
      'ubuntu': {
        ensure_packages(['nis'], {
            ensure => purged,
        })
      }
      'sles':{
        ensure_packages(['ypserv'], {
            ensure => absent,
        })
      }
      default: {
        ensure_resource('service', ['ypserv'], {
            ensure => 'stopped',
            enable => false
        })
      }
    }
  }
}

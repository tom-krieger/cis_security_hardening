# @summary 
#    Ensure LDAP server is not enabled 
#
# The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It 
# is a service that provides a method for looking up information from a central database.
#
# Rationale:
# If the system will not need to act as an LDAP server, it is recommended that the software be 
# disabled to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::ldapd':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ldapd (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['operatingsystem'].downcase() {
      'ubuntu': {
        ensure_packages(['slapd'], {
            ensure => purged,
        })
      }
      'sles': {
        ensure_packages(['openldap2'], {
            ensure => absent,
        })
      }
      default: {
        ensure_resource('service', ['slapd'], {
            ensure => 'stopped',
            enable => false
        })
      }
    }
  }
}

# @summary 
#    Ensure LDAP client is not installed 
#
# The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. 
# It is a service that provides a method for looking up information from a central database.
# 
# Rationale:
# If the system will not need to act as an LDAP client, it is recommended that the software 
# be removed to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::ldap_client':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ldap_client (
  Boolean $enforce = false,
) {
  if $enforce {
    $pkg = $facts['os']['name'].downcase() ? {
      'ubuntu' => 'ldap-utils',
      'debian' => 'ldap-utils',
      'sles'   => 'openldap2-clients',
      default  => 'openldap-clients',
    }

    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged'
    }

    ensure_packages($pkg, {
        ensure => $ensure,
    })
  }
}

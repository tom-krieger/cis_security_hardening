# @summary 
#    Ensure NIS Client is not installed (Automated)
#
# The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server 
## directory service protocol used to distribute system configuration files. The NIS client 
# (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.
#
# Rationale:
# The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer 
# overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by 
# such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service 
# be removed.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::nis_client':
#       enforce => true,
#   }
#
# @example
#   include cis_security_hardening::rules::nis_client
#
# @api private
class cis_security_hardening::rules::nis_client (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['operatingsystem'].downcase() == 'ubuntu' {
      $pkg = 'nis'
    } else {
      $pkg = 'ypbind'
    }

    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages($pkg, {
        ensure => $ensure,
    })
  }
}

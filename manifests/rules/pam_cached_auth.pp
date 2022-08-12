# @summary 
#    Ensure PAM prohibits the use of cached authentications after one day
#
# The operating system must be configured such that Pluggable Authentication Module (PAM) 
# prohibits the use of cached authentications after one day.
#
# Rationale:
# If cached authentication information is out-of-date, the validity of the authentication 
# information may be questionable.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::pam_cached_auth':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::pam_cached_auth (
  Boolean $enforce = false
) {
  if $enforce {
    file { '/etc/sssd/conf.d/cis.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file_line { 'pam cached auth':
      ensure  => 'present',
      path    => '/etc/sssd/conf.d/cis.conf',
      line    => 'offline_credentials_expiration = 1',
      match   => '^#?offline_credentials_expiration',
      require => File['/etc/sssd/conf.d/cis.conf']
    }
  }
}

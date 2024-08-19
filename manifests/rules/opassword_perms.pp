# @summary 
#    Ensure permissions on /etc/security/opasswd are configured
#
# /etc/security/opasswd and it's backup /etc/security/opasswd.old hold user's
# previous passwords if pam_unix or pam_pwhistory is in use on the system
#
# Rationale:
# It is critical to ensure that /etc/security/opasswd is protected from unauthorized
# access. Although it is protected by default, the file permissions could be changed either
# inadvertently or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::opasswd_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::opassword_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/security/opasswd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/security/opasswd.old':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }
}

# @summary 
#    Ensure permissions on /etc/passwd are configured 
#
# The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable 
# for these utilities to operate.
# 
# Rationale:
# It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by 
# default, the file permissions could be changed either inadvertently or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::passwd_perms':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::passwd_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/passwd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }
}

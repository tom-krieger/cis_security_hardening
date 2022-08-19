# @summary 
#    Ensure permissions on /etc/group- are configured 
#
# The /etc/group- file contains a backup list of all the valid groups defined in the system. 
# 
# Rationale:
# It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by 
# default, the file permissions could be changed either inadvertently or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::passwd_bak_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::passwd_bak_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/passwd-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }
  }
}

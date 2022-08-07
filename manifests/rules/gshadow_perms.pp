# @summary 
#    Ensure permissions on /etc/gshadow are configured (Automated)
#
# The /etc/gshadow file is used to store the information about groups that is critical to 
# the security of those accounts, such as the hashed password and other security information.
#
# Rationale:
# If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking 
# program against the hashed password to break it. Other security information that is stored in the 
# /etc/gshadow file (such as group administrators) could also be useful to subvert the group.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::gshadow_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gshadow_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/gshadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  }
}

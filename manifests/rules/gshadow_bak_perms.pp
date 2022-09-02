# @summary 
#    Ensure permissions on /etc/gshadow- are configured 
#
# The /etc/gshadow- file is used to store backup information about groups that is critical 
# to the security of those accounts, such as the hashed password and other security information.
#
# Rationale:
# It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. 
# Although it is protected by default, the file permissions could be changed either inadvertently 
# or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::gshadow_bak_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gshadow_bak_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['operatingsystem'].downcase() == 'debian' {
      $attrs = {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0640',
      }
    } else {
      $attrs = {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0000',
      }
    }
    file { '/etc/gshadow-':
      * => $attrs,
    }
  }
}

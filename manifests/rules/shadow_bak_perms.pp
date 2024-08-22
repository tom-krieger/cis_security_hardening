# @summary
#    Ensure permissions on /etc/shadow- are configured
#
# The /etc/shadow- file is used to store backup information about user accounts that is critical to the security
# of those accounts, such as the hashed password and other security information.
#
# Rationale:
# It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is
# protected by default, the file permissions could be changed either inadvertently or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::shadow_bak_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_bak_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'debian' {
      if $facts['os']['release']['major'] > '10' {
        $attrs = {
          ensure => file,
          owner  => 'root',
          group  => 'root',
          mode   => '0000',
        }
      } else {
        $attrs = {
          ensure => file,
          owner  => 'root',
          group  => 'root',
          mode   => '0600',
        }
      }
    } else {
      $attrs = {
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0000',
      }
    }
    file { '/etc/shadow-':
      * => $attrs,
    }
  }
}

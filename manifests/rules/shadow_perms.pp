# @summary 
#    Ensure permissions on /etc/shadow are configured 
#
# The /etc/shadow file is used to store the information about user accounts that is critical to the security 
# of those accounts, such as the hashed password and other security information.
#
# Rationale:
# If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program 
# against the hashed password to break it. Other security information that is stored in the /etc/shadow 
# file (such as expiration) could also be useful to subvert the user accounts.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::shadow_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shadow_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/shadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }
  }
}

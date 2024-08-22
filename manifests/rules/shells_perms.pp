# @summary 
#    Ensure permissions on /etc/shells are configured
#
# /etc/shells is a text file which contains the full pathnames of valid login shells. This file
# is consulted by chsh and available to be queried by other programs.
#
# Rationale:
# It is critical to ensure that the /etc/shells file is protected from unauthorized access.
# Although it is protected by default, the file permissions could be changed either
# inadvertently or through malicious actions.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::shells_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::shells_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/shells':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }
}

# @summary 
#    Ensure permissions on /etc/group are configured 
#
# The /etc/group file contains a list of all the valid groups defined in the system. The command below 
# allows read/write access for root and read access for everyone else.
#
# Rationale:
# The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs 
# to be readable as this information is used with many non-privileged programs.
#
# @param enforce
#    Enforce the rule 
#
# @example
#   class { 'cis_security_hardening::rules::group_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::group_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file { '/etc/group':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }
}

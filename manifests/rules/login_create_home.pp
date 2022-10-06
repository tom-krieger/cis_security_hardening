# @summary
#    Ensure upon user creation a home directory is assigned.
#
# The operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory.
#
# Rationale:
# If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they 
# should own.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::login_create_home':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::login_create_home (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'create_home':
      ensure             => present,
      path               => '/etc/login.defs',
      match              => '^CREATE_HOME',
      line               => 'CREATE_HOME yes',
      append_on_no_match => true,
    }
  }
}

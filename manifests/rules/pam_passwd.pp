# @summary
#    Ensure system-auth is used when changing passwords
#
# The operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth 
# when changing passwords.
#
# Rationale:
# Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods. 
# PAM operates in a top-down processing model and if the modules are not listed in the correct order, an 
# important security function could be bypassed if stack entries are not centralized.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::pam_passwd':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::pam_passwd (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'pam_passwd':
      ensure             => present,
      path               => '/etc/pam.d/passwd',
      match              => '^password\s+substack\s+system-auth',
      line               => 'password   substack     system-auth',
      append_on_no_match => true,
    }
  }
}

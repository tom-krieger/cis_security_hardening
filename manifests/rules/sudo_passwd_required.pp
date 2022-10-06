# @summary
#    Ensure users password required for privilege escalation when using sudo
#
# The Linux operating system must use the invoking user's password for privilege escalation when using "sudo"
#
# Rationale:
# The sudoers security policy requires that users authenticate themselves before they can use sudo. When sudoers 
# requires authentication, it validates the invoking user's credentials. If the rootpw, targetpw, or runaspw 
# flags are defined and not disabled, by default the operating system will prompt the invoking user for the "root" 
# user password. For more information on each of the listed configurations, reference the sudoers(5) manual page.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sudo_passwd_required':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sudo_passwd_required (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'targetpw':
      ensure             => present,
      path               => '/etc/sudoers',
      match              => '^Defaults !targetpw',
      line               => 'Defaults !targetpw',
      append_on_no_match => true,
    }

    file_line { 'rootpw':
      ensure             => present,
      path               => '/etc/sudoers',
      match              => '^Defaults !rootpw',
      line               => 'Defaults !rootpw',
      append_on_no_match => true,
    }

    file_line { 'runaspw':
      ensure             => present,
      path               => '/etc/sudoers',
      match              => '^Defaults !runaspw',
      line               => 'Defaults !runaspw',
      append_on_no_match => true,
    }
  }
}

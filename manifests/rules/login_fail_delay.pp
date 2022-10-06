# @summary
#    Ensure delay between logon prompts on failure
#
# The operating system must be configured so that the delay between logon prompts following a failed console 
# logon attempt is at least four seconds.
#
# Rationale:
# Configuring the operating system to implement organization-wide security implementation guides and security 
# checklists verifies compliance with federal standards and establishes a common security baseline across DoD 
# that reflects the most restrictive security posture consistent with operational requirements.
#
# Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components 
# of the system that affect the security posture and/or functionality of the system. Security-related parameters are 
# those parameters impacting the security state of the system, including the parameters required to satisfy other 
# security control requirements. Security-related parameters include, for example, registry settings; account, file, 
# and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
#
# @param enforce
#    Enforce the rule.
#
# @param fail_delay
#    The delay to wait after a failed login.
#
# @example
#   class { 'cis_security_hardening::rules::login_fail_delay':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::login_fail_delay (
  Boolean $enforce    = false,
  Integer $fail_delay = 4,
) {
  if $enforce {
    file_line { 'fail_delay':
      ensure             => present,
      path               => '/etc/login.defs',
      match              => '^FAIL_DELAY',
      line               => "FAIL_DELAY ${fail_delay}",
      append_on_no_match => true,
    }
  }
}

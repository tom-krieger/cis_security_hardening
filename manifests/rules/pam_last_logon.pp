# @summary 
#    Ensure last successful account logon is displayed upon logon
#
# The operating system must display the date and time of the last successful account 
# logon upon logon
#
# Rationale:
# Configuration settings are the set of parameters that can be changed in hardware, software, 
# or firmware components of the system that affect the security posture and/or functionality of 
# the system. Security-related parameters are those parameters impacting the security state of the 
# system, including the parameters required to satisfy other security control requirements. 
# Security-related parameters include, for example: registry settings; account, file, directory 
# permission settings; and settings for functions, ports, protocols, services, and remote connections.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::pam_last_logon':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::pam_last_logon (
  Boolean $enforce = false,
) {
  if $enforce {
    Pam { 'pam-login-last-logon':
      ensure    => present,
      service   => 'login',
      type      => 'session',
      control   => 'required',
      module    => 'pam_lastlog.so',
      arguments => ['showfailed'],
    }
  }
}

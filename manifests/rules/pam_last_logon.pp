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
# @api private
class cis_security_hardening::rules::pam_last_logon (
  Boolean $enforce = false,
) {
  if $enforce {
    if ($facts['os']['name'].downcase() == 'redhat') and ($facts['os']['release']['major'] == '7') {
      $service = 'postlogin'
    } else {
      $service = 'login'
    }

    file_line { 'pam last logon':
      ensure             => present,
      path               => "/etc/oam.d/${service}",
      match              => 'session\s+required\s+pam_lastlog.so',
      line               => 'session        required        pamlastlog.so showfailed',
      append_on_no_match => true,
    }

    # Pam { "pam-login-last-logon-${service}":
    #   ensure    => present,
    #   service   => $service,
    #   type      => 'session',
    #   control   => 'required',
    #   module    => 'pam_lastlog.so',
    #   arguments => ['showfailed'],
    # }
  }
}

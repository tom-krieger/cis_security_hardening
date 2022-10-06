# @summary 
#    Ensure sudo authentication timeout is configured correctly
#
# sudo caches used credentials for a default of 5 minutes. This is for ease of use when there are multiple 
# administrative tasks to perform. The timeout can be modified to suit local security policies.
#
# Rationale:
# Setting a timeout value reduces the window of opportunity for unauthorized privileged access to another user.
#
# @param enforce
#    Enforce the rule.
# @param timeout
#    sudo timeout in minutes.
#
# @example
#   class { 'cis_security_hardening::rules::sudo_timeout':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sudo_timeout (
  Boolean $enforce = false,
  Integer $timeout = 5,
) {
  if $enforce {
    file_line { 'set sudo timeout':
      path               => '/etc/sudoers',
      match              => '^Defaults\s+timestamp_timeout=',
      line               => "Defaults timestamp_timeout=${timeout}",
      append_on_no_match => true,
    }
  }
}

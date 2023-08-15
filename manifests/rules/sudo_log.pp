# @summary 
#    Ensure sudo log file exists 
#
# sudo can use a custom log file
#
# Rationale:
# A sudo log file simplifies auditing of sudo commands
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sudo_log':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sudo_log (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'sudo logfile':
      path               => '/etc/sudoers',
      match              => 'Defaults.*logfile\s*=',
      append_on_no_match => true,
      line               => 'Defaults logfile=/var/log/sudo.log',
      after              => '# Defaults specification',
    }
  }
}

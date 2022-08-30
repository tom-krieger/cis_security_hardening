# @summary 
#    Ensure sudo commands use pty 
#
# sudo can be configured to run only from a psuedo-pty
#
# Rationale:
# Attackers can run a malicious program using sudo which would fork a background process 
# that remains even when the main program has finished executing.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sudo_use_pty':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::sudo_use_pty (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'sudo use pty':
      path               => '/etc/sudoers',
      match              => 'Defaults.*use_pty',
      append_on_no_match => true,
      line               => 'Defaults use_pty',
      after              => '# Defaults specification',
    }
  }
}

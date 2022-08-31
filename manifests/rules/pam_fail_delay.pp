# @summary
#    Ensure loging delay after failed logon attempt
#
# The operating system must enforce a delay of at least 4 seconds between logon prompts 
# following a failed logon attempt.
#
# Rationale:
# Limiting the number of logon attempts over a certain time interval reduces the chances 
# that an unauthorized user may gain access to an account.
#
# @param enforce
#    Enforce the rule.
# @param delay
#    Delay between failed logins.
#
# @example
#   class { 'cis_security_hardening::rules::pam_fail_delay':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::pam_fail_delay (
  Boolean $enforce = false,
  Integer $delay   = 4000000,
) {
  if $enforce {
    Pam { 'pam-common-auth-fail-delay':
      ensure    => present,
      service   => 'common-auth',
      type      => 'auth',
      control   => 'required',
      module    => 'pam_faildelay.so',
      arguments => ["delay=${delay}"],
    }
  }
}

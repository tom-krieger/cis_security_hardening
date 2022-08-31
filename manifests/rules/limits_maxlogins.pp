# @summary 
#    Ensure maxlogins is 10 or less
#
# he operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.
#
# Rationale:
# The Ubuntu operating system management includes the ability to control the number of users and user sessions that 
# utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the 
# risks related to DoS attacks.
# This requirement addresses concurrent sessions for information system accounts and does not address concurrent 
# sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined 
# based upon mission needs and the operational environment for each system.
#
# @param enforce
#    Enforce the rule
# @param maxlogins
#    Maximun logins to set.
#
# @example
#   class 'cis_security_hardening::rules::limits_maxlogins':
#     enforce => true,
#     maxlogins => 5,
#   }
#
# @api public
class cis_security_hardening::rules::limits_maxlogins (
  Boolean $enforce   = false,
  Integer $maxlogins = 10,
) {
  if $enforce {
    file_line { 'set maxlogins':
      ensure             => present,
      path               => '/etc/security/limits.conf',
      match              => "^*\s+hard\s+maxlogins\s+${maxlogins}",
      line               => "*\thard\tmaxlogins\t${maxlogins}",
      append_on_no_match => true,
    }
  }
}

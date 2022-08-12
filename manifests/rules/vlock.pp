# @summary A 
#    Ensure vlock is installed
#
# The operating system must allow users to directly initiate a session lock for all connection types.
#
# Rationale:
# A session lock is a temporary action taken when a user stops work and moves away from the immediate 
# physical vicinity of the information system but does not want to log out because of the temporary 
# nature of the absence.
#
# The session lock is implemented at the point where session activity can be determined. Rather than 
# be forced to wait for a period of time to expire before the user session can be locked, the Ubuntu 
# operating systems need to provide users with the ability to manually invoke a session lock so users 
# may secure their session if they need to temporarily vacate the immediate physical vicinity.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::vlock':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::vlock (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['vlock'], {
      ensure => present,
    })
  }
}

# @summary
#    Ensure the "tmux" package installed
#
# The operating system must have the tmux package installed. 
# Rationale:
# A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity 
# of the information system but does not want to log out because of the temporary nature of the absence. The session lock 
# is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time 
# to expire before the user session can be locked, the operating system needs to provide users with the ability to manually 
# invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical 
# vicinity.
#
# Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single 
# screen. Red Hat endorses tmux as the recommended session controlling package.
#
# Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::tmux_package':
#     enforce => true,
#   }
# 
# @api private
class cis_security_hardening::rules::tmux_package (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['tmux'], {
        ensure => installed,
    })
  }
}

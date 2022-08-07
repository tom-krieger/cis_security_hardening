# @summary
#    Ensure xinetd is not installed (Automated)
#
# The eXtended InterNET Daemon ( xinetd ) is an open source super daemon that replaced the original inetd 
# daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly 
# respond to service requests.
#
# Rationale:
# If there are no xinetd services required, it is recommended that the package be removed.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::xinetd {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::xinetd (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['xinetd'], {
        ensure => $ensure,
    })
  }
}

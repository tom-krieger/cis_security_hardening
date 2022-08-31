# @summary
#    Ensure SELinux is installed 
#
# SELinux provides Mandatory Access Controls.
#
# Rationale:
# Without a Mandatory Access Control system installed only the default Discretionary Access Control system 
# will be available.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::selinux':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::selinux (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['libselinux'], {
        ensure => present,
    })
  }
}

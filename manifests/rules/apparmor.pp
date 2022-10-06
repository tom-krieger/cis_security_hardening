# @summary
#    Ensure AppArmor is installed 
#
# AppArmor provides Mandatory Access Controls.
#
# Rationale:
# Without a Mandatory Access Control system installed only the default Discretionary 
# Access Control system will be available.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::apparmor':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apparmor (
  Boolean $enforce = false,
) {
  if  $enforce {
    case $facts['osfamily'].downcase() {
      'debian': {
        ensure_packages(['apparmor-utils', 'apparmor'], {
            ensure => present,
        })
      }
      'suse': {
        exec { 'install apparmor':
          command => 'zypper install -t pattern apparmor',
          path    => ['/usr/bin', '/bin'],
          unless  => 'rpm -q apparmor-docs apparmor-parser apparmor-profiles apparmor-utils libapparmor1',
        }
      }
      default: {
        # Nothing to do yet
      }
    }
  }
}

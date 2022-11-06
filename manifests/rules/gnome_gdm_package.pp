# @summary
#    Ensure GNOME Display Manager is removed 
#
# The GNOME Display Manager (GDM) is a program that manages graphical display servers and handles graphical user logins.
#
# Rationale:
# If a Graphical User Interface (GUI) is not required, it should be removed to reduce the attack surface of the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::gnome_gdm_package':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gnome_gdm_package (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['family'].downcase() {
      'suse': {
        $pkg = 'gdm'
        $ensure = 'absent'
      }
      default: {
        $pkg = 'gdm3'
        $ensure = 'purged'
      }
    }

    ensure_packages($pkg, {
        ensure => $ensure,
    })
  }
}

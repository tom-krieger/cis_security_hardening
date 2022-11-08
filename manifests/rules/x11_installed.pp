# @summary 
#    Ensure X Window System is not installed 
#
# The X Window System provides a Graphical User Interface (GUI) where users can have multiple 
# windows in which to run programs and various add on. The X Windows system is typically used 
# on workstations where users login, but not on servers where users typically do not login.
#
# Rationale:
# Unless your organization specifically requires graphical login access via X Windows, remove it 
# to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::x11_installed':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::x11_installed (
  Boolean $enforce = false,
) {
  $x11_installed = fact('cis_security_hardening.x11.installed')
  $x11_packages = fact('cis_security_hardening.x11.packages')

  if  $enforce and $x11_installed != undef and $x11_installed {
    $x11_packages.each |$pkg| {
      # do not uninstall these packages due to dependances needed on the system
      if $pkg !~ /^xorg-x11-font/ and $pkg !~ /^xorg-x11-server-utils/ {
        $ensure = $facts['os']['family'].downcase() ? {
          'suse'  => 'absent',
          default => 'purged',
        }
        ensure_packages([$pkg], {
            ensure => $ensure,
        })
      }
    }
  }
}

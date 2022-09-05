# @summary 
#    Ensure user's session lock is enabled
#
# The operating system must retain a user's session lock until that user reestablishes access using 
# established identification and authentication procedures.
#
# Rationale:
# A session lock is a temporary action taken when a user stops work and moves away from the immediate 
# physical vicinity of the information system but does not want to log out because of the temporary 
# nature of the absence.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class 'cis_security_hardening::rules::gdm_lock_enabled':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_lock_enabled (
  Boolean $enforce = false,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    exec { 'gdm lock enabled':
      command => 'gsettings set org.gnome.desktop.screensaver lock-enabled true',
      path    => ['/bin', '/usr/bin'],
      unless  => 'test "$(gsettings get org.gnome.desktop.screensaver lock-enabled)" = "true"',
    }
  }
}

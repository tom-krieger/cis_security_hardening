# @summary
#    Ensure GNOME Screensaver period of inactivity is configured
#
# The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.
#
# Rationale:
# A session time-out lock with the screensaver is a temporary action taken when a user stops work and moves away from the 
# immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. 
# Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating 
# systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
#
# The screensaver is implemented at the point where session activity can be determined and/or controlled.
#
# @param enforce
#    Enforce the rule.
# @param timeout
#    The idle time.
# @param lockdelay
#    
#
# @example
#   class { 'cis_security_hardening::rules::gdm_screensaver':
#     enforce => true,
#     timeout => 900,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_screensaver (
  Boolean $enforce   = false,
  Integer $timeout   = 900,
  Integer $lockdelay = 5,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    exec { 'gdm screensaver enabled':
      command => "gsettings set org.gnome.desktop.session idle-delay \"unit32 ${timeout}\"", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin'],
      unless  => "test \"$(gsettings get org.gnome.desktop.session idle-delay)\" = \"unit32 ${timeout}\"",
    }

    exec { 'gdm screensaver ilde activates':
      command => 'gsettings set org.gnome.desktop.screensaver idle-activation-enabled "true"',
      path    => ['/bin', '/usr/bin'],
      unless  => 'test "$(gsettings get org.gnome.desktop.session idle-delayidle-activation-enabled)" = "true"',
    }

    exec { 'gdm screensaver locktime':
      command => "gsettings set org.gnome.desktop.screensaver lock-delay \"unit32 ${lockdelay}\"", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin'],
      unless  => "test \"$(gsettings get org.gnome.desktop.screensaver lock-delay)\" = \"unit32 ${lockdelay}\"",
    }
  }
}

# @summary
#    Ensure overriding the screensaver lock-delay setting is prevented
#
# The operating system must prevent a user from overriding the screensaver lock-delay setting for the graphical user interface.
#
# Rationale:
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity 
# of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user 
# to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify 
# when a user's session has idled and take action to initiate the session lock.
#
# The session lock is implemented at the point where session activity can be determined and/or controlled.
#
# @param enforce
#    Enforce the rule.
# @param timeout
#    Lock delay timeout.
#
# @example
#   include cis_security_hardening::rules::gdm_lock_delay
class cis_security_hardening::rules::gdm_lock_delay (
  Boolean $enforce = false,
  Integer $timeout = 900,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    exec { 'gdm lock delay':
      command => "gsettings set org.gnome.desktop.screensaver lock-delay ${timeout}", #lint:ignore:security_class_or_define_parameter_in_exec lint:ignore:140chars
      path    => ['/bin', '/usr/bin'],
      unless  => "test \"$(gsettings get org.gnome.desktop.screensaver lock-delay)\" = \"${timeout}\"",
    }
  }
}

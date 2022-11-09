# @summary
#    Ensure the SELinux state is enforcing or permissive 
#
# Set SELinux to enable when the system is booted.
#
# Rationale:
# SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times.
#
# @param enforce
#    Enforce the rule
#
# @param state
#    SELinux state to set
#
# @param auto_reboot
#    Trigger a reboot if this rule creates a change. Defaults to true.
#
# @example
#   class { 'cis_security_hardening::rules::selinux_state':
#       enforce => true,
#       state => 'permissive',
#   }
#
# @api private
class cis_security_hardening::rules::selinux_state (
  Boolean $enforce                       = false,
  Enum['enforcing', 'permissive'] $state = 'enforcing',
  Boolean $auto_reboot                   = true,
) {
  if $enforce {
    $notify = $auto_reboot ? {
      true  => Class['cis_security_hardening::reboot'],
      false => [],
    }

    ensure_resource('file', '/etc/selinux/config', {
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
        notify => $notify
    })

    file_line { 'selinux_enforce':
      path     => '/etc/selinux/config',
      line     => "SELINUX=${state}",
      match    => 'SELINUX=',
      multiple => true,
      notify   => $notify,
    }
  }
}

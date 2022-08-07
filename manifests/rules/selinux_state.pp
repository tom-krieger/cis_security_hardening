# @summary
#    Ensure the SELinux state is enforcing or permissive (Automated)
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
) {
  if $enforce {
    ensure_resource('file', '/etc/selinux/config', {
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
        notify => Reboot['after_run']
    })

    file_line { 'selinux_enforce':
      path     => '/etc/selinux/config',
      line     => "SELINUX=${state}",
      match    => 'SELINUX=',
      multiple => true,
      notify   => Reboot['after_run'],
    }
  }
}

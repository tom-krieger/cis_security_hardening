# @summary
#    Ensure AppArmor is enabled in the bootloader configuration (Automated)
#
# Configure AppArmor to be enabled at boot time and verify that it has not been 
# overwritten by the bootloader boot parameters.
#
# Rationale:
# AppArmor must be enabled at boot time in your bootloader configuration to ensure 
# that the controls it provides are not overridden.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::apparmor_bootloader':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::apparmor_bootloader (
  Boolean $enforce = false,
) {
  if  $enforce and
  ($facts['osfamily'].downcase() == 'debian' or $facts['osfamily'].downcase() == 'suse') {
    kernel_parameter { 'apparmor':
      value  => '1',
      notify => Exec['apparmor-grub-config'],
    }

    kernel_parameter { 'security':
      value  => 'apparmor',
      notify => Exec['apparmor-grub-config'],
    }

    file_line { 'cmdline_definition':
      line   => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
      path   => '/etc/default/grub',
      match  => '^GRUB_CMDLINE_LINUX_DEFAULT',
      notify => Exec['apparmor-grub-config'],
    }

    case $facts['osfamily'].downcase() {
      'debian': {
        $cmd = 'update-grub'
      }
      'suse': {
        $cmd = 'grub2-mkconfig -o /boot/grub2/grub.cfg'
      }
      default: {
        $cmd = ''
      }
    }

    if ! empty($cmd) {
      exec { 'apparmor-grub-config':
        command     => $cmd,
        path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        refreshonly => true,
      }
    }
  }
}

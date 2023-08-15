# @summary 
#    Ensure SELinux is not disabled in bootloader configuration 
#
# Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.
#
# Rationale:
# SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::selinux_bootloader':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::selinux_bootloader (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['release']['major'] {
      '7', '8': {
        file_line { 'cmdline_definition':
          line   => 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"',
          path   => '/etc/default/grub',
          match  => '^GRUB_CMDLINE_LINUX_DEFAULT',
          notify => Exec['selinux-grub-config'],
        }
        exec { 'selinux-grub-config':
          command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
      }
      '9': {
        exec { 'enable selinux with grubby':
          command => 'grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"',
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          unless  => 'test -z "$(grubby --info=ALL | grep -Po \'(selinux|enforcing)=0\\b\')"',
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

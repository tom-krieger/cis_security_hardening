# @summary
#    Ensure bootloader password is set 
#
# Setting the boot loader password will require that anyone rebooting the system must enter a password 
# before being able to set command line boot parameters
#
# Notes:
# * This recommendation is designed around the grub2 bootloader, if LILO or another bootloader is in use in 
#    your environment enact equivalent settings. Replace `/boot/grub2/grub.cfg with the appropriate grub 
#    configuration file for your environment
# * For older grub2 based systems:
#   o The superuser/user information and password should not be contained in the
#     /etc/grub.d/00_header file. The information can be placed in any /etc/grub.d file as long as that file 
#     is incorporated into grub.cfg. The user may prefer to enter this data into a custom file, such as 
#     /etc/grub.d/40_custom so it is not overwritten should the Grub package be updated.
#   o If placing the information in a custom file, do not include the "cat << EOF" and "EOF" lines as the content 
#     is automatically added from these files.
#
# Rationale:
# Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot 
# parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux 
# at boot time).
#
# @param enforce
#    Enforce the rule
#
# @param grub_password_pbkdf2
#    Encrypted grub password.
#
# @example
#   class { 'cis_security_hardening::rules::grub_password':
#       enforce              => true,
#       grub_password_pbkdf2 => 'grub.pbkdf2.sha512.10000.943.......',
#   }
# 
# @api private
class cis_security_hardening::rules::grub_password (
  Boolean $enforce             = false,
  String $grub_password_pbkdf2 = '',
) {
  if $enforce and $grub_password_pbkdf2 == '' {
    echo { 'No grub password defined':
      message  => 'Enforcing a grub boot password needs a grub password to be defined. Please define an encrypted in Hiera.',
      loglevel => 'warning',
      withpath => false,
    }
  }

  $efi_grub_cfg = "/boot/efi/EFI/${facts['os']['name'].downcase()}/grub.cfg"

  case $facts['os']['family'].downcase() {
    'redhat': {
      if $enforce and $grub_password_pbkdf2 != '' {
        $notify =  fact('cis_security_hardening.efi') ? {
          true    => [Exec['bootpw-grub-config'], Exec['bootpw-grub-config-efi']],
          default => Exec['bootpw-grub-config'],
        }

        file { '/boot/grub2/user.cfg':
          ensure  => file,
          content => "GRUB2_PASSWORD=${grub_password_pbkdf2}",
          owner   => 'root',
          group   => 'root',
          mode    => '0600',
          notify  => $notify,
        }

        exec { 'bootpw-grub-config':
          command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }

        exec { 'bootpw-grub-config-efi':
          command     => "grub2-mkconfig -o ${efi_grub_cfg}",
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
      } else {
        file { '/boot/grub2/user.cfg':
          ensure => file,
          owner  => 'root',
          group  => 'root',
          mode   => '0600',
        }
      }
    }
    'debian': {
      if $enforce and $grub_password_pbkdf2 != '' {
        $notify =  fact('cis_security_hardening.efi') ? {
          true    => [Exec['bootpw-grub-config-ubuntu'], Exec['bootpw-grub-config-ubuntu-efi']],
          default => Exec['bootpw-grub-config-ubuntu'],
        }

        file_line { 'grub-unrestricted':
          ensure             => present,
          path               => '/etc/grub.d/10_linux',
          line               => 'CLASS="--class gnu-linux --class gnu --class os --unrestricted"',
          match              => '^CLASS="--class gnu-linux --class gnu --class os"',
          append_on_no_match => false,
          notify             => $notify,
        }

        file { '/etc/grub.d/50_custom':
          ensure  => file,
          content => epp('cis_security_hardening/rules/common/ubuntu_grub_user.cfg.epp', {
              password => $grub_password_pbkdf2,
          }),
          owner   => 'root',
          group   => 'root',
          mode    => '0755',
          notify  => $notify,
        }

        exec { 'bootpw-grub-config-ubuntu':
          command     => 'update-grub',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }

        exec { 'bootpw-grub-config-ubuntu-efi':
          command     => "update-grub -o ${efi_grub_cfg}",
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
      }
    }
    'suse': {
      if  $enforce and $grub_password_pbkdf2 != '' {
        $notify =  fact('cis_security_hardening.efi') ? {
          true    => [Exec['bootpw-grub-config-sles'], Exec['bootpw-grub-config-sles-efi']],
          default => Exec['bootpw-grub-config-sles'],
        }

        file { '/etc/grub.d/40_custom':
          ensure  => file,
          content => epp('cis_security_hardening/rules/common/ubuntu_grub_user.cfg.epp', {
              password => $grub_password_pbkdf2,
          }),
          owner   => 'root',
          group   => 'root',
          mode    => '0755',
          notify  => $notify,
        }

        exec { 'bootpw-grub-config-sles':
          command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }

        exec { 'bootpw-grub-config-sles-efi':
          command     => "grub2-mkconfig -o ${efi_grub_cfg}",
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
      }
    }
    default: {
      # nothing to do yet
    }
  }
}

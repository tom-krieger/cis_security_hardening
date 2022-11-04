# @summary 
#    Ensure permissions on bootloader config are configured 
#
# The grub configuration file contains information on boot settings and passwords for unlocking boot 
# options. The grub configuration is usually located at /boot/grub2/grub.cfg and linked as /etc/grub2.cfg. 
# Additional settings can be found in the /boot/grub2/user.cfg file.
#
# Rationale:
# Setting the permissions to read and write for root only prevents non-root users from seeing the boot 
# parameters or changing them. Non-root users who read the boot parameters may be able to identify 
# weaknesses in security upon boot and be able to exploit them.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::grub_bootloader_config':
#       enforce => true,
#   }
#
# @example
#   include cis_security_hardening::rules::grub_bootloader_config
#
# @api private
class cis_security_hardening::rules::grub_bootloader_config (
  Boolean $enforce = false,
) {
  if $enforce {
    $filename = $facts['os']['name'].downcase() ? {
      'centos'    => '/boot/grub2/grub.cfg',
      'almalinux' => '/boot/grub2/grub.cfg',
      'rocky'     => '/boot/grub2/grub.cfg',
      'redhat'    => '/boot/grub2/grub.cfg',
      'ubuntu'    => '/boot/grub/grub.cfg',
      'debian'    => '/boot/grub/grub.cfg',
      'sles'      => '/boot/grub2/grub.cfg',
      default     => '',
    }

    if ! empty($filename) {
      file { $filename:
        ensure => file,
        owner  => 'root',
        group  => 'root',
        mode   => '0400',
      }
    }

    if $facts['os']['family'].downcase() == 'debian' {
      file_line { 'correct grub.cfg permissions':
        path                                  => '/usr/sbin/grub-mkconfig',
        line                                  => "  chmod 400 \${grub_cfg}.new || true",
        match                                 => '\s+chmod.*444',
        multiple                              => true,
        replace_all_matches_not_matching_line => true,
        append_on_no_match                    => false,
      }
    }

    if $facts['efi'] and has_key($facts['mountpoints'], '/boot/efi') {
      $device = $facts['mointpoints']['/boot/efi']['device']
      $uuid   = $facts['partitions'][$device]['uuid']
      $line   = "UUID=${uuid}  /boot/efi       vfat    umask=0077,fmask=0077,uid=0,gid=0      0        1"

      file_line { 'fix /boot/efi':
        ensure             => present,
        path               => '/etc/fstab',
        match              => "^UUID=${uuid}\s+/boot/efi\s+vfat",
        line               => $line,
        append_on_no_match => true,
      }
    }
  }
}

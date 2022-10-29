# @summary 
#    Ensure mounting of squashfs filesystems is disabled 
#
# The squashfs filesystem type is a compressed read-only Linux filesystem embedded in 
# small footprint systems (similar to cramfs ). A squashfs image can be used without 
# having to first decompress the image.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of 
# the system. If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::squashfs'
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::squashfs (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'rocky', 'almalinux': {
        kmod::install { 'squashfs':
          command => '/bin/false',
        }
        kmod::blacklist { 'squashfs': }
      }
      'centos', 'redhat': {
        if $facts['operatingsystemmajrelease'] > '7' {
          kmod::install { 'squashfs':
            command => '/bin/false',
          }
          kmod::blacklist { 'squashfs': }
        } else {
          kmod::install { 'squashfs':
            command => '/bin/true',
          }
        }
      }
      default: {
        kmod::install { 'squashfs':
          command => '/bin/true',
        }
      }
    }
  }
}

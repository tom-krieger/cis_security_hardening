# @summary 
#    Ensure mounting of FAT filesystems is disabled 
#
# The FAT filesystem format is primarily used on older windows systems and portable 
# USB drives or flash modules. It comes in three types FAT12 , FAT16 , and FAT32 all 
# of which are supported by the vfat kernel module.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of 
# the system. If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::fat':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::fat (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'ubuntu', 'debian': {
        kmod::install { 'vfat':
          command => '/bin/true',
        }
      }
      'centos', 'almalinux', 'rocky', 'redhat': {
        case $facts['os']['release']['major'] {
          '7': {
            kmod::install { 'fat':
              command => '/bin/true',
            }
            kmod::install { 'vfat':
              command => '/bin/true',
            }
            kmod::install { 'msdos':
              command => '/bin/true',
            }
          }
          '8': {
            kmod::install { 'vfat':
              command => '/bin/true',
            }
          }
          default: {}
        }
      }
      'sles': {
        kmod::install { 'fat':
          command => '/bin/true',
        }
        kmod::install { 'vfat':
          command => '/bin/true',
        }
        kmod::install { 'msdos':
          command => '/bin/true',
        }
      }
      default: {}
    }
  }
}

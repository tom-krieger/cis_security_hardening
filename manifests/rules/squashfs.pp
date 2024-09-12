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
      'rocky', 'almalinux', 'centos': {
        kmod::install { 'squashfs':
          command => '/bin/false',
        }
        kmod::blacklist { 'squashfs': }
      }
      'redhat': {
        if $facts['os']['release']['major'] > '7' {
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
      'debian': {
        if $facts['os']['release']['major'] > '10' {
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
      'ubuntu': {
        if $facts['os']['release']['major'] >= '20' {
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

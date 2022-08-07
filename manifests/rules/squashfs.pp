# @summary 
#    Ensure mounting of squashfs filesystems is disabled (Automated)
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
    kmod::install { 'squashfs':
      command => '/bin/true',
    }
  }
}

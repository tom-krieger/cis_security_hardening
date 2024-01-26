# @summary 
#    Ensure mounting of freevxfs filesystems is disabled 
#
# The freevxfs filesystem type is a free version of the Veritas type filesystem. 
# This is the primary filesystem type for HP-UX operating systems.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface 
# of the system. If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::freevxfs':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::freevxfs (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '20' {
      kmod::install { 'freevxfs':
        command => '/bin/false',
      }
    } else {
      kmod::install { 'freevxfs':
        command => '/bin/true',
      }
    }
  }
}

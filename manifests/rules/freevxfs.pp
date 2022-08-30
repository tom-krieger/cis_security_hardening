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
# @api public
class cis_security_hardening::rules::freevxfs (
  Boolean $enforce = false,
) {
  if $enforce {
    kmod::install { 'freevxfs':
      command => '/bin/true',
    }
  }
}

# @summary 
#    Ensure mounting of hfsplus filesystems is disabled 
#
# The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs 
# that allows you to mount Mac OS filesystems.s a hierarchical filesystem that 
# allows you to mount Mac OS filesystems.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the 
# system. If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::hfsplus':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::hfsplus (
  Boolean $enforce = false,
) {
  if $enforce {
    kmod::install { 'hfsplus':
      command => '/bin/true',
    }
  }
}

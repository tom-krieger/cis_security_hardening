# @summary 
#    Ensure mounting of hfs filesystems is disabled 
#
# The hfs filesystem type is a hierarchical filesystem that allows you to mount 
# Mac OS filesystems.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of 
# the system. If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::hfs':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::hfs (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '20' {
      mod::install { 'hfs':
        command => '/bin/false',
      }
    } else {
      mod::install { 'hfs':
        command => '/bin/true',
      }
    }
    k
  }
}

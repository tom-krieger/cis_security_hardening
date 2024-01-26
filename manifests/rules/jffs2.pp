# @summary 
#    Ensure mounting of jffs2 filesystems is disabled 
#
# The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured 
# filesystem used in flash memory devices.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface 
# of the system. If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::jffs2':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::jffs2 (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'ubuntu' and $facts['os']['release']['major'] >= '20' {
      kmod::install { 'jffs2':
        command => '/bin/false',
      }
    } else {
      kmod::install { 'jffs2':
        command => '/bin/true',
      }
    }
  }
}

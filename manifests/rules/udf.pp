# @summary 
#    Ensure mounting of udf filesystems is disabled 
#
# The udf filesystem type is the universal disk format used to implement ISO/IEC 
# 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data 
# storage on a broad range of media. This filesystem type is necessary to support 
# writing DVDs and newer optical disc formats.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the system. 
# If this filesystem type is not needed, disable it.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class is_security_hardening::rules::common::udf {
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::udf (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['operatingsystem'].downcase() {
      'rocky', 'almalinux': {
        kmod::install { 'udf':
          command => '/bin/false',
        }
        kmod::blacklist { 'udf': }
      }
      'redhat': {
        if $facts['operatingsystemmajrelease'] > '7' {
          kmod::install { 'udf':
            command => '/bin/false',
          }
          kmod::blacklist { 'udf': }
        } else {
          kmod::install { 'udf':
            command => '/bin/true',
          }
        }
      }
      default: {
        kmod::install { 'udf':
          command => '/bin/true',
        }
      }
    }
  }
}

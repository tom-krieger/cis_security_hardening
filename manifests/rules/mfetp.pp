# @summary 
#    Ensure Endpoint Security for Linux Threat Prevention is installed
#
# The operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).
#
# Rationale:
# Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the 
# operating system or other system components may remain vulnerable to the exploits presented by undetected software 
# flaws.
#
# To support this requirement, the operating system may have an integrated solution incorporating continuous scanning 
# using HBSS and periodic scanning using other tools, as specified in the requirement.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::mfetp':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::mfetp (
  Boolean $enforce = false,
) {
  if $enforce {
    package { 'mfetp':
      ensure => installed,
    }
  }
}

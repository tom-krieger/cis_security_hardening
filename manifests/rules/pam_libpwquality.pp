# @summary
#    Ensure libpwquality is installed (Automated)
#
# The libpwquality package provides common functions for password quality checking
#
# Rationale:
# Strong passwords reduce the risk of systems being hacked through brute force
# methods.
#
#
# @param enforce
#    Enforce the rule
# @example
#   class {'cis_security_hardening::rules::pam_libpwquality': 
#    enforce +> true,
#   }
#
# @api privare
class cis_security_hardening::rules::pam_libpwquality (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['libpwquality'], {
        ensure => installed,
    })
  }
}

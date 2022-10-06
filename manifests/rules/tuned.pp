# @summary
#    Ensure the tuned package has not been installed on the system.
#
# The tuned package must not be installed unless it is mission essential. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, 
# provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
#
# The tuned package contains a daemon that tunes the system settings dynamically. It does so by monitoring the usage of 
# several system components periodically. Based on that information, components will then be put into lower or higher power 
# savings modes to adapt to the current usage. The tuned package is not needed for normal OS operations.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::tuned':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::tuned (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['tuned'], {
        ensure => $ensure,
    })
  }
}

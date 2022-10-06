# @summary
#    Ensure the iprutils package has not been installed on the system.
#
# The iprutils package must not be installed unless it is mission essential. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, 
# provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
#
# The iprutils package provides a suite of utilities to manage and configure SCSI devices supported by the ipr SCSI storage 
# device driver.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::iprutils':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::iprutils (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    ensure_packages(['iprutils'], {
        ensure => $ensure,
    })
  }
}

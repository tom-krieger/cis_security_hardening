# @summary
#    Ensure the sendmail package is not installed.
#
# The operating system must not have the sendmail package installed. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, 
# provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).
#
# Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration 
# software not related to requirements or providing a wide array of functionality not required for every mission, but 
# which cannot be disabled.
#
# Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a 
# non-essential capability is disabled is to not have the capability installed.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sendmail':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sendmail (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }
    ensure_packages(['sendmail'], {
        ensure => $ensure,
    })
  }
}

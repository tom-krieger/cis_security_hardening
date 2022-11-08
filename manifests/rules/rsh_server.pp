# @summary 
#    Ensure rsh-server is not installed
#
# The operating system must not have the rsh-server package installed.
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
# software, not related to requirements or providing a wide array of functionality not required for every mission, but which 
# cannot be disabled.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::rsh_server':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rsh_server (
  Boolean $enforce = false
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }

    $pkgs = $facts['os']['name'].downcase() ? {
      'ubuntu' => 'rsh-server',
      'debian' => 'rsh-server',
      default  => ''
    }

    unless empty($pkgs) {
      ensure_packages($pkgs, {
          ensure => $ensure,
      })
    }
  }
}

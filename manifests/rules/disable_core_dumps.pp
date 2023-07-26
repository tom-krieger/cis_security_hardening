# @summary
#    Ensure the operating system disables the storing core dumps
#
# The operating system must disable the kernel.core_pattern. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission 
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase 
# the risk to the platform by providing additional attack vectors.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::disable_core_dumps':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::disable_core_dumps (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'kernel.core_pattern':
        ensure   => present,
        value  => '|/bin/false',
        notify => Exec['reload-sysctl-system'],
    }
  }
}

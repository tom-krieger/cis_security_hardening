# @summary
#    Ensure the operating system restricts exposed kernel pointer addresses access
#
# The operating system must restrict exposed kernel pointer addresses access. 
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::kptr_restrict':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::kptr_restrict (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'kernel.kptr_restrict':
        ensure => present,
        value  => '1',
        notify => Exec['reload-sysctl-system'],
    }
  }
}

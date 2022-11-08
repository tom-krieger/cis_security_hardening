# @summary#
#    Ensure the operating system restricts usage of ptrace to descendant processes
#
# The operating system must restrict usage of ptrace to descendant processes. 
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::ptrace_scope':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ptrace_scope (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'kernel.yama.ptrace_scope':
        value  => '1',
        notify => Exec['reload-sysctl-system'],
    }
  }
}

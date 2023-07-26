# @summary
#    Ensure the operating system prevents privilege escalation through the kernel by disabling access to the bpf syscall
#
# The operating system must disable access to network bpf syscall from unprivileged processes.
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
#   class { 'cis_security_hardening::rules::unprivileged_bpf_disabled':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::unprivileged_bpf_disabled (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'kernel.unprivileged_bpf_disabled':
        ensure => present,
        value  => '1',
        notify => Exec['reload-sysctl-system'],
    }
  }
}

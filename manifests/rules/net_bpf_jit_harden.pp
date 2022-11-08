# @summary
#    Ensure the operating system enables hardening for the BPF JIT
#
# The operating system must enable hardening for the Berkeley Packet Filter Just-in-time compiler.
#
# Rationale:
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or 
# mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. 
# They increase the risk to the platform by providing additional attack vectors.
#
# Enabling hardening for the Berkeley Packet Filter (BPF) Just-in-time (JIT) compiler aids in mitigating JIT spraying 
# attacks. Setting the value to "2" enables JIT hardening for all users.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::net_bpf_jit_harden':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::net_bpf_jit_harden (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'net.core.bpf_jit_harden':
        value  => 2,
        notify => Exec['reload-sysctl-system'],
    }
  }
}

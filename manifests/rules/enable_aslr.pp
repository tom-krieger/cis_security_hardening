# @summary 
#    Ensure address space layout randomization (ASLR) is enabled 
#
# Address space layout randomization (ASLR) is an exploit mitigation technique which randomly 
# arranges the address space of key data areas of a process.
# 
# Rationale:
# Randomly placing virtual memory regions will make it difficult to write memory page exploits 
# as the memory placement will be consistently shifting.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::enable_aslr':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::enable_aslr (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl { 'kernel.randomize_va_space':
      ensure    => present,
      permanent => 'yes',
      value     => 2,
    }
  }
}

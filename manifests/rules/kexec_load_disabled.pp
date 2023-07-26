# @summary
#    Ensure kernel image loading is disabled
#
# The operating system must prevent the loading of a new kernel for later execution. 
#
# Rationale:
#
# Changes to any software components can have significant effects on the overall security of the operating system. This 
# requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.
#
# Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) 
# from being loaded. Kexec can be used subvert the entire secureboot process and should be avoided at all costs especially 
# since it can load unsigned kernel images.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::kexec_load_disabled':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::kexec_load_disabled (
  Boolean $enforce = false,
) {
  if $enforce {
    sysctl {
      'kernel.kexec_load_disabled':
        ensure => present,
        value  => 1,
        notify => Exec['reload-sysctl-system'],
    }
  }
}

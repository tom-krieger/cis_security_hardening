# @summary 
#    Ensure kdump service is not enabled
#
# The operating system must disable kernel core dumps so that it can fail to a secure state if system initialization 
# fails, shutdown fails or aborts fail.
# Rationale:
# Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may 
# consume a considerable amount of disk space and may result in denial of service by exhausting the available space 
# on the target file system partition.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class 'cis_security_hardening::rules::kdump_service':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::kdump_service (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', 'kdump.service', {
        enable => false,
        ensure => stopped,
    })
  }
}

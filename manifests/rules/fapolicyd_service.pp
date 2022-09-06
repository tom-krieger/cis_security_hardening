# @summary
#    Ensure "fapolicyd" is enabled and running
#
# The "fapolic4y" module must be enabled. 
#
# Rationale:
# The organization must identify authorized software programs and permit execution of authorized software. The process 
# used to identify software programs that are authorized to execute on organizational information systems is commonly 
# referred to as whitelisting. Utilizing a whitelist provides a configuration management method for allowing the execution 
# of only authorized software. Using only authorized software decreases risk by limiting the number of potential 
# vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup.
#
# User home directories/folders may contain information of a sensitive nature. Non- privileged users should coordinate any 
# sharing of information with an SA through shared resources.
#
# RHEL 8 operating systems ship with many optional packages. One such package is a file access policy daemon called "fapolicyd". 
# "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can 
# be used to either blacklist or whitelist processes or file access.
#
# Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional. 
# The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.
#
# Satisfies: SRG-OS-000368-GPOS-00154, SRG-OS-000370-GPOS-00155, SRG-OS-000480- GPOS-00232
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::fapolicyd_service':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::fapolicyd_service (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_resource('service', 'fapolicyd', {
        ensure => running,
        enable => true,
    })
  }
}

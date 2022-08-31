# @summary 
#    Ensure auditd is installed 
#
# auditd is the userspace component to the Linux Auditing System. It's responsible for writing audit 
# records to the disk.
#
# Rationale:
# The capturing of system events provides system administrators with information to allow them to 
# determine if unauthorized access to their system is occurring.
#
# @param enforce
#    Sets rule enforcementen. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param packages
#    Packages for auditd to install
#
# @example
#   class { 'cis_security_hardening::rules::auditd_package':
#             enforce => true,
#             packages => ['audit', 'audit-libs'],
#   }
#
# @api public
class cis_security_hardening::rules::auditd_package (
  Boolean $enforce = false,
  Array $packages  = [],
) {
  if $enforce {
    $packages.each |$pkg| {
      ensure_packages([$pkg], {
          ensure => installed,
      })
    }
  }
}

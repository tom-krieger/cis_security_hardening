# @summary 
#    Ensure the audit configuration is immutable 
#
# Set system audit so that audit rules cannot be modified with auditctl . Setting the flag "-e 2" 
# forces audit to be put in immutable mode. Audit changes can only be made on system reboot.
#
# Rationale:
# In immutable mode, unauthorized users cannot execute changes to the audit system to potentially 
# hide malicious activity and then put the audit rules back. Users would most likely notice a 
# system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_immutable':
#             enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_immutable (
  Boolean $enforce                 = false,
) {
  if $enforce {
    concat::fragment { 'make config immutable':
      order   => '999',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-e 2',
    }
  }
}

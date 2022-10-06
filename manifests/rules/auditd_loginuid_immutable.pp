# @summary
#    Ensure the audit system prevents unauthorized changes to logon UIDs
#
# The audit system must protect logon UIDs from unauthorized change.
#
# Rationale:
# Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.
#
# Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit system 
# activity.
#
# In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the 
# audit rules back. A system reboot would be noticeable and a system administrator could then investigate the unauthorized changes.
#
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059- GPOS-00029
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_loginuid_immutable':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_loginuid_immutable (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'make loginuid immutable':
      order   => '997',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '--loginuid-immutable',
    }
  }
}

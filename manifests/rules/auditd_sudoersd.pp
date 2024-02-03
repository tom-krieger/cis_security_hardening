# @summary
#    Ensure the operating system generates audit records for all account creations, modifications, disabling, and termination events
#
# The operating system must generate audit records for all account creations, modifications, disabling, and termination events that 
# affect /etc/sudoers.d/.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to 
# establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
# 
# Satisfies: SRG-OS-000062-GPOS-00031, SRG-OS-000004-GPOS-00004, SRG-OS-000037- GPOS-00015, SRG-OS-000042-GPOS-00020, 
# SRG-OS-000062-GPOS-00031, SRG-OS- 000304-GPOS-00121, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG- OS-000470-GPOS-00214, 
# SRG-OS-000471-GPOS-00215, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, 
# SRG-OS-000304-GPOS-00121, CCI-002884, SRG-OS-000466-GPOS-00210, SRG-OS-000476- GPOS-00221
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_sudoersd':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_sudoersd (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch sudoers.d rule 1':
      order   => '217',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/sudoers.d/ -p wa -k identity',
    }
  }
}

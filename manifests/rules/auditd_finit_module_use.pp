# @summary 
#    Ensure successful and unsuccessful uses of the finit_module syscall are recorded
#
# The operating system must generate audit records for successful/unsuccessful uses of the finit_module syscall.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it 
# would be difficult to establish, correlate, and investigate the events relating to an incident or identify 
# those responsible for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000477-GPOS-00222
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_finit_module_use':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_finit_module_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch finit_module command rule 1':
      order   => '187',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S finit_module -F auid>=${uid} -F auid!=4294967295 -k module_chng",
    }

    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch finit_module command rule 2':
        order   => '188',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S finit_module -F auid>=${uid} -F auid!=4294967295 -k module_chng",
      }
    }
  }
}

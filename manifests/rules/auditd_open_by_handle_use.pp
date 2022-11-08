# @summary 
#    Ensure successful and unsuccessful uses of the open_by_handle_at system call are recorded
#
# The operating system must generate audit records for successful/unsuccessful uses of the open_by_handle_at system call.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it would be 
# difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible 
# for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000474-GPOS-00219
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_open_by_handle_use':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_open_by_handle_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch open_by_handle_at command rule 1':
      order   => '168',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=${uid} -F auid!=4294967295 -k perm_access",
    }

    concat::fragment { 'watch open_by_handle_at command rule 2':
      order   => '169',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=${uid} -F auid!=4294967295 -k perm_access",
    }

    if  $facts['os']['architecture'] == 'x86_64' or $facts['os']['architecture'] == 'amd64' {
      concat::fragment { 'watch open_by_handle_at command rule 3':
        order   => '170',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=${uid} -F auid!=4294967295 -k perm_access",
      }

      concat::fragment { 'watch open_by_handle_at command rule 4':
        order   => '171',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=${uid} -F auid!=4294967295 -k perm_access",
      }
    }
  }
}

# @summary 
#    Ensure successful and unsuccessful attempts to use the lremovexattr system call are recorded
#
# The operating system must generate audit records for any use of the lremovexattr system call.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it 
# would be difficult to establish, correlate, and investigate the events relating to an incident or identify 
# those responsible for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206, SRG-OS-000466- GPOS-00210
#
# @param enforce 
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_llremovexattr_use':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_lremovexattr_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch lremovexattr command rule 1':
      order   => '164',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S lremovexattr -F auid>=${uid} -F auid!=4294967295 -k perm_mod",
    }

    concat::fragment { 'watch lremovexattr command rule 2':
      order   => '165',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod',
    }

    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch lremovexattr command rule 3':
        order   => '166',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S lremovexattr -F auid>=${uid} -F auid!=4294967295 -k perm_mod",
      }

      concat::fragment { 'watch lremovexattr command rule 4':
        order   => '167',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod',
      }
    }
  }
}

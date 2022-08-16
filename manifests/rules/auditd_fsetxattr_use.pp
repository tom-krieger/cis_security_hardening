# @summary 
#    Ensure successful and unsuccessful attempts to use the fsetxattr system call are recorded
#
# The operating system must generate audit records for any use of the fsetxattr system call.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it would 
# be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible 
# for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000462-GPOS-00206
#
# @param enforce 
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_fsetxattr_use':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_fsetxattr_use (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch fsetxattr command rule 1':
      order   => '152',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
    }

    concat::fragment { 'watch fsetxattr command rule 2':
      order   => '153',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod',
    }

    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch fsetxattr command rule 3':
        order   => '154',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
      }

      concat::fragment { 'watch fsetxattr command rule 4':
        order   => '155',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod',
      }
    }
  }
}

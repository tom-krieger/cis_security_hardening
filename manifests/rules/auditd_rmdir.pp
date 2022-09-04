# @summary
#    Ensure audit of the rmdir syscall
#
# The operating system must audit all uses of the rmdir syscall.
#
# Rationale:
# If the system is not configured to audit certain activities and write them to an audit log, it is more 
# difficult to detect and track system compromises and damages incurred during a system compromise.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_rmdir':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_rmdir (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch rmdir rule 1':
      order   => '210',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S rmdir -F auid>=${uid} -F auid!=4294967295 -k delete",
    }
    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch rmdir rule 2':
        order   => '211',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S rmdir -F auid>=${uid} -F auid!=4294967295 -k delete",
      }
    }
  }
}

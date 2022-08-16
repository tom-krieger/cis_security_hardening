# @summary 
#    Ensure file deletion events by users are collected (Automated)
#
# Monitor the use of system calls associated with the deletion or renaming of files and file 
# attributes. This configuration statement sets up monitoring for the unlink (remove a file), 
# unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) 
# system calls and tags them with the identifier "delete".
#
# Rationale:
# Monitoring these calls from non-privileged users could provide a system administrator with evidence 
# that inappropriate removal of files and file attributes associated with protected files is occurring. 
# While this audit option will look at all events, system administrators will want to look for specific 
# privileged files that are being deleted or altered.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_delete':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_delete (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $auid = $facts['operatingsystem'].downcase() ? {
      'rocky' => 'unset',
      default => '4294967295',
    }
    concat::fragment { 'watch deletes rule 1':
      order   => '31',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=${auid} -k delete",
    }
    if  $facts['architecture'] == 'x86_64' or
    $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch deletes rule 2':
        order   => '32',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=${auid} -k delete",
      }
    }
  }
}

# @summary 
#    Ensure changes to system administration scope (sudoers) is collected (Automated)
#
# Monitor scope changes for system administrations. If the system has been properly configured 
# to force system administrators to log in as themselves first and then use the sudo command to 
# execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers 
# will be written to when the file or its attributes have changed. The audit records will be tagged 
# with the identifier "scope."
# 
# Rationale:
# Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope 
# of system administrator activity.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_scope':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_scope (
  Boolean $enforce                 = false,
) {
  if $enforce {
    concat::fragment { 'watch scope rule 1':
      order   => '101',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/sudoers -p wa -k scope',
    }
    concat::fragment { 'watch scope rule 2':
      order   => '102',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/sudoers.d/ -p wa -k scope',
    }
  }
}

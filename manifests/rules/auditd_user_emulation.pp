# @summary 
#    Ensure actions as another user are always logged 
#
# sudo provides users with temporary elevated privileges to perform operations, either as the superuser or another user.
#
# Rationale:
# Creating an audit log of users with temporary elevated privileges and the operation(s) they performed is essential to reporting. 
# Administrators will want to correlate the events written to the audit trail with the records written to sudo's logfile to verify 
# if unauthorized commands have been executed.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_user_emulation':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_user_emulation (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch user emulation rule 1':
      order   => '196',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -k user_emulation',
    }

    if  $facts['os']['architecture'] == 'x86_64' or $facts['os']['architecture'] == 'amd64' {
      concat::fragment { 'watch user emulation rule 2':
        order   => '197',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=unset -k user_emulation',
      }
    }
  }
}

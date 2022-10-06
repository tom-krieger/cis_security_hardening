# @summary 
#    Ensure execution of privileged functions is recorded
#
# The operating system must prevent all software from executing at higher privilege levels than users executing 
# the software and the audit system must be configured to audit the execution of privileged functions.
#
# Rationale:
# In certain situations, software applications/programs need to execute with elevated privileges to perform required 
# functions. However, if the privileges required for execution are at a higher level than the privileges assigned to 
# organizational users invoking such applications/programs, those users are indirectly provided with greater privileges 
# than assigned by the organizations.
#
# Some programs and processes are required to operate at a higher privilege level and therefore should be excluded 
# from the organization-defined software list after review.
#
# Satisfies: SRG-OS-000326-GPOS-00126, SRG-OS-000327-GPOS-00127
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class  'cis_security_hardening::rules::auditd_privileged_functions_use':
#     enforce = true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_privileged_functions_use (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['os']['name'].downcase() == 'redhat' and $facts['os']['release']['major'] == '7' {
      $rule1 = '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid'
      $rule2 = '-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid'
      $rule3 = '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid'
      $rule4 = '-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid'
    } else {
      $rule1 = '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv'
      $rule2 = '-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv'
      $rule3 = '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv'
      $rule4 = '-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv'
    }
    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch privileged_functions command rule 3':
        order   => '191',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $rule3,
      }

      concat::fragment { 'watch privileged_functions command rule 4':
        order   => '192',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $rule4,
      }
    } else {
      concat::fragment { 'watch privileged_functions command rule 1':
        order   => '189',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $rule1,
      }

      concat::fragment { 'watch privileged_functions command rule 2':
        order   => '190',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $rule2,
      }
    }
  }
}

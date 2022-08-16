# @summary 
#    Ensure discretionary access control permission modification events are collected
#
# Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls 
# that affect file permissions and attributes. The following commands and system calls effect the permissions, ownership and various 
# attributes of files.
# * chmod
# * fchmod
# * fchmodat
# * chown
# * fchown
# * fchownat
# * lchown
# * setxattr
# * lsetxattr
# * fsetxattr
# * removexattr 
# * lremovexattr 
# * fremovexattr
# 
# In all cases, an audit record will only be written for non-system user ids and will ignore Daemon events. All audit records will 
# be tagged with the identifier "perm_mod."
#
# Rationale:
# Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or 
# policy violation.
# 
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_discretionary_access':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_discretionary_access (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch discretionary access control rule 1':
      order   => '198',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod',
    }

    concat::fragment { 'watch discretionary access control rule 2':
      order   => '199',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod',
    }

    concat::fragment { 'watch discretionary access control rule 3':
      order   => '200',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod', #lint:ignore:140chars
    }

    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch discretionary access control rule 4':
        order   => '201',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod',
      }

      concat::fragment { 'watch discretionary access control rule 5':
        order   => '202',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod',
      }

      concat::fragment { 'watch discretionary access control rule 6':
        order   => '203',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod', #lint:ignore:140chars
      }
    }
  }
}

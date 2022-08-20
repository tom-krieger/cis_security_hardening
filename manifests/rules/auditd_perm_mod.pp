# @summary 
#    Ensure discretionary access control permission modification events are collected 
#
# Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track 
# changes for system calls that affect file permissions and attributes. The chmod , fchmod and fchmodat system 
# calls affect the permissions associated with a file. The chown , fchown , fchownat and lchown system calls 
# affect owner and group attributes on a file. The setxattr , lsetxattr , fsetxattr (set extended file attributes) 
# and removexattr , lremovexattr , fremovexattr (remove extended file attributes) control extended file attributes. 
# In all cases, an audit record will only be written for non-system user ids (auid >= 1000) and will ignore Daemon 
# events (auid = 4294967295). All audit records will be tagged with the identifier "perm_mod."
#
# Rationale:
# Monitoring for changes in file attributes could alert a system administrator to activity that could indicate 
# intruder activity or policy violation.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_perm_mod':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_perm_mod (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    $os = fact('operatingsystem') ? {
      undef   => 'unknown',
      default => fact('operatingsystem').downcase()
    }

    case $os {
      'rocky', 'almalinux': {
        $auid = 'unset'
        $content_rule1 = "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule2 = "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule3 = "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${uid} -F auid!=${auid} -k perm_mod" #lint:ignore:140chars
        $content_rule4 = "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule5 = "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule6 = "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${uid} -F auid!=${auid} -k perm_mod" #lint:ignore:140chars
      }
      default: {
        $auid = '4294967295'
        $content_rule1 = "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule2 = "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule3 = "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=${uid} -F auid!=${auid} -k perm_mod" #lint:ignore:140chars
        $content_rule4 = "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule5 = "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=${uid} -F auid!=${auid} -k perm_mod"
        $content_rule6 = "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=${uid} -F auid!=${auid} -k perm_mod" #lint:ignore:140chars
      }
    }

    concat::fragment { 'watch perm mod rule 1':
      order   => '91',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $content_rule1,
    }
    concat::fragment { 'watch perm mod rule 2':
      order   => '92',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $content_rule2,
    }
    concat::fragment { 'watch perm mod rule 3':
      order   => '93',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $content_rule3,
    }
    if $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch perm mod rule 4':
        order   => '94',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $content_rule4,
      }
      concat::fragment { 'watch perm mod rule 5':
        order   => '95',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $content_rule5,
      }
      concat::fragment { 'watch perm mod rule 6':
        order   => '96',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $content_rule6,
      }
    }
  }
}

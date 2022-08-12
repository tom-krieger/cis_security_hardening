# @summary
#    Ensure system administrator actions (sudolog) are collected (Automated)
#
# Monitor the sudo log file. If the system has been properly configured to disable the use 
# of the su command and force all administrators to have to log in first and then use sudo 
# to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. 
# Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will 
# be opened for write and the executed administration command will be written to the log.
#
# Rationale:
# Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file 
# itself has been tampered with. Administrators will want to correlate the events written to the audit 
# trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a compliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_actions':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_actions (
  Boolean $enforce                 = false,
) {
  if $enforce {
    case $facts['operatingsystem'].downcase() {
      'redhat', 'centos', 'almalinux', 'rocky': {
        if $facts['operatingsystemmajrelease'] >= '8' {
          concat::fragment { 'watch admin actions rule 1':
            order   => 21,
            target  => $cis_security_hardening::rules::auditd_init::rules_file,
            content => '-w /var/log/sudo.log -p wa -k actions',
          }
        } else {
          if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
            concat::fragment { 'watch admin actions rule 1':
              order   => 21,
              target  => $cis_security_hardening::rules::auditd_init::rules_file,
              content => '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions',
            }
          }

          concat::fragment { 'watch admin actions rule 2':
            order   => 22,
            target  => $cis_security_hardening::rules::auditd_init::rules_file,
            content => '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions',
          }
        }
      }
      'ubuntu': {
        if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
          concat::fragment { 'watch admin actions rule 1':
            order   => 21,
            target  => $cis_security_hardening::rules::auditd_init::rules_file,
            content => '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions',
          }
        }

        concat::fragment { 'watch admin actions rule 2':
          order   => 22,
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions',
        }
      }
      'debian', 'suse': {
        concat::fragment { 'watch admin actions rule 1':
          order   => 21,
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /var/log/sudo.log -p wa -k actions',
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

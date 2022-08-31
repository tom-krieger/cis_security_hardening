# @summary 
#    Ensure events that modify date and time information are collected 
#
# Capture events where the system date and/or time has been modified. The parameters in this section are set to 
# determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) 
# stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and 
# timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon 
# exit, tagging the records with the identifier "time-change"
#
# Rationale:
# Unexpected changes in system date and/or time could be a sign of malicious activity on the system.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_time_change':
#             enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_time_change (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $os = fact('os.name') ? {
      undef   => 'unknown',
      default => fact('os.name').downcase()
    }
    if $os == 'rocky' or $os == 'almalinux' {
      concat::fragment { 'watch for date-time-change rule 1':
        order   => '121',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change',
      }
      concat::fragment { 'watch for date-time-change rule 3':
        order   => '123',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-w /etc/localtime -p wa -k time-change',
      }
      if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
        concat::fragment { 'watch for date-time-change rule 2':
          order   => '122',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change',
        }
      }
    } else {
      concat::fragment { 'watch for date-time-change rule 1':
        order   => '121',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
      }
      concat::fragment { 'watch for date-time-change rule 2':
        order   => '122',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-a always,exit -F arch=b32 -S clock_settime -k time-change',
      }
      concat::fragment { 'watch for date-time-change rule 3':
        order   => '123',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-w /etc/localtime -p wa -k time-change',
      }

      if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
        concat::fragment { 'watch for date-time-change rule 4':
          order   => '124',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
        }
        concat::fragment { 'watch for date-time-change rule 5':
          order   => '125',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-a always,exit -F arch=b64 -S clock_settime -k time-change',
        }
      }
    }
  }
}

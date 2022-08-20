# @summary 
#    Ensure unsuccessful unauthorized file access attempts are collected 
#
# Monitor for unsuccessful attempts to access files. The parameters below are associated with 
# system calls that control creation ( creat ), opening ( open , openat ) and truncation 
# ( truncate , ftruncate ) of files. An audit log record will only be written if the user is a 
# non- privileged user (auid >= 1000), is not a Daemon event (auid=4294967295) and if the 
# system call returned EACCES (permission denied to the file) or EPERM (some other permanent 
# error associated with the specific system call). All audit records will be tagged with the 
# identifier "access."
#
# Rationale:
# Failed attempts to open, create or truncate files could be an indication that an individual 
# or process is trying to gain unauthorized access to the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_access':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_access (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $auid = $facts['operatingsystem'].downcase() ? {
      'rocky'     => 'unset',
      'almalinux' => 'unset',
      default     => '4294967295',
    }
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }

    concat::fragment { 'watch access rule 1':
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      order   => '11',
    }

    concat::fragment { 'watch access rule 2':
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      order   => '12',
    }

    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch access rule 3':
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
        order   => '13',
      }

      concat::fragment { 'watch access rule 4':
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
        order   => '14',
      }
    }
  }
}

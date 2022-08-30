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
# @api public
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
    $os = fact('operatingsystem') ? {
      undef   => 'unknown',
      default => fact('operatingsystem').downcase()
    }

    $content_rule1 = $os ? {
      'almalinux' => "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      'rocky'     => "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      default     => "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
    }

    $content_rule2 = $os ? {
      'almalinux' => "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      'rocky'     => "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      default     => "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
    }

    concat::fragment { 'watch access rule 1':
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $content_rule1,
      order   => '11',
    }

    concat::fragment { 'watch access rule 2':
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $content_rule2,
      order   => '12',
    }

    if $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      $content_rule3 = $os ? {
        'almalinux' => "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
        'rocky'     => "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
        default     => "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      }
      $content_rule4 = $os ? {
        'almalinux' => "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access",  #lint:ignore:140chars
        'rocky'     => "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access",  #lint:ignore:140chars
        default     => "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=${uid} -F auid!=${auid} -k access", #lint:ignore:140chars
      }
      concat::fragment { 'watch access rule 3':
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $content_rule3,
        order   => '13',
      }

      concat::fragment { 'watch access rule 4':
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => $content_rule4,
        order   => '14',
      }
    }
  }
}

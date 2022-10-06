# @summary 
#    Ensure successful file system mounts are collected 
#
# Monitor the use of the mount system call. The mount (and umount ) system call controls the 
# mounting and unmounting of file systems. The parameters below configure the system to create 
# an audit record when the mount system call is used by a non-privileged user
#
# Rationale:
# It is highly unusual for a non privileged user to mount file systems to the system. While tracking 
# mount commands gives the system administrator evidence that external media may have been mounted (based 
# on a review of the source of the mount and confirming it's an external media type), it does not 
# conclusively indicate that data was exported to the media. System administrators who wish to determine 
# if data were exported, would also have to track successful open , creat and truncate system calls requiring 
# write access to a file under the mount point of the external media file system. This could give a fair 
# indication that a write occurred. The only way to truly prove it, would be to track successful writes to the 
# external media. Tracking write system calls could quickly fill up the audit log and is not recommended. 
# Recommendations on configuration options to track data export to media is beyond the scope of this document.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_mounts':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_mounts (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch mounts rule 1':
      order   => '81',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F arch=b32 -S mount -F auid>=${uid} -F auid!=4294967295 -k mounts",
    }
    if $facts['operatingsystem'].downcase() == 'redhat' {
      concat::fragment { 'watch mounts rule 3':
        order   => '215',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F path=/usr/bin/mount -F auid>=${uid} -F auid!=4294967295 -k privileged-mount",
      }
    }
    if  $facts['architecture'] == 'x86_64' or $facts['architecture'] == 'amd64' {
      concat::fragment { 'watch mounts rule 2':
        order   => '82',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => "-a always,exit -F arch=b64 -S mount -F auid>=${uid} -F auid!=4294967295 -k mounts",
      }
    }
  }
}

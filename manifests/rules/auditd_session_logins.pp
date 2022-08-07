# @summary 
#    Ensure session initiation information is collected (Automated)
#
# Monitor session initiation events. The parameters in this section track changes to the files 
# associated with session events. The file /var/run/utmp file tracks all currently logged in users. 
# All audit records will be tagged with the identifier "session." The /var/log/wtmp file tracks 
# logins, logouts, shutdown, and reboot events. The file /var/log/btmp keeps track of failed login 
# attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp . All audit records 
# will be tagged with the identifier "logins."
#
# Rationale:
# Monitoring these files for changes could alert a system administrator to logins occurring at unusual 
# hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally 
# log in).
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_session_logins':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_session_logins (
  Boolean $enforce                 = false,
) {
  if $enforce {
    concat::fragment { 'watch session rule 1':
      order   => '111',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /var/run/utmp -p wa -k session',
    }

    concat::fragment { 'watch session rule 2':
      order   => '112',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /var/log/wtmp -p wa -k logins',
    }

    concat::fragment { 'watch session rule 3':
      order   => '113',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /var/log/btmp -p wa -k logins',
    }
  }
}

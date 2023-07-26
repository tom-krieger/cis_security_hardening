# @summary 
#    Ensure login and logout events are collected 
#
# Monitor login and logout events. The parameters below track changes to files associated with login/logout events. 
# The file /var/log/lastlog maintain records of the last time a user successfully logged in. The /var/run/failock 
# directory maintains records of login failures via the pam_faillock module.
# 
# Rationale:
# Monitoring login/logout events could provide a system administrator with information associated with brute force 
# attacks against user logins.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_logins':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_logins (
  Boolean $enforce                 = false,
) {
  if $enforce {
    concat::fragment { 'logins policy rule 1':
      order   => '51',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /var/log/lastlog -p wa -k logins',
    }

    case $facts['os']['family'].downcase() {
      'redhat': {
        concat::fragment { 'logins policy rule 2':
          order   => '52',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /var/run/faillock/ -p wa -k logins',
        }
      }
      'debian': {
        concat::fragment { 'logins policy rule 2':
          order   => '52',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /var/log/faillog -p wa -k logins',
        }

        if $facts['os']['release']['major'] < '11' {
          concat::fragment { 'logins policy rule 3':
            order   => '53',
            target  => $cis_security_hardening::rules::auditd_init::rules_file,
            content => '-w /var/log/tallylog -p wa -k logins',
          }
        }
      }
      'suse': {
        concat::fragment { 'logins policy rule 2':
          order   => '52',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /var/log/faillog -p wa -k logins',
        }

        concat::fragment { 'logins policy rule 3':
          order   => '53',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /var/log/tallylog -p wa -k logins',
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

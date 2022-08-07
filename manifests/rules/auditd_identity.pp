# @summary 
#    Ensure events that modify user/group information are collected (Automated)
#
# Record events affecting the group , passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd 
# (old passwords, based on remember parameter in the PAM configuration) files. The parameters in this section 
# will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) 
# and tag them with the identifier "identity" in the audit log file.
#
# Rationale:
# Unexpected changes to these files could be an indication that the system has been compromised and that an 
# unauthorized user is attempting to hide their activities or compromise additional accounts.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_identity':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_identity (
  Boolean $enforce                 = false,
) {
  if $enforce {
    concat::fragment { 'watch identity rule 1':
      order   => '41',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/group -p wa -k identity',
    }
    concat::fragment { 'watch identity rule 2':
      order   => '42',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/passwd -p wa -k identity',
    }
    concat::fragment { 'watch identity rule 4':
      order   => '44',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/shadow -p wa -k identity',
    }
    concat::fragment { 'watch identity rule 5':
      order   => '45',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /etc/security/opasswd -p wa -k identity',
    }
    if $facts['operatingsystem'].downcase() != 'sles' {
      concat::fragment { 'watch identity rule 3':
        order   => '43',
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => '-w /etc/gshadow -p wa -k identity',
      }
    }
  }
}

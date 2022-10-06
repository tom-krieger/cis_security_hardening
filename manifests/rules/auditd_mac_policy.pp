# @summary 
#    Ensure events that modify the system's Mandatory Access Controls are collected 
#
# Monitor SELinux mandatory access controls. The parameters below monitor any write access (potential additional, 
# deletion or modification of files in the directory) or attribute changes to the /etc/selinux or directory.
#
# Rationale:
# Changes to files in these directories could indicate that an unauthorized user is attempting to modify access 
# controls and change security contexts, leading to a compromise of the system.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_mac_policy':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_mac_policy (
  Boolean $enforce                 = false,
) {
  if $enforce {
    case $facts['osfamily'].downcase() {
      'redhat', 'suse': {
        concat::fragment { 'mac policy rule 1':
          order   => '61',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /etc/selinux/ -p wa -k MAC-policy',
        }
        concat::fragment { 'mac policy rule 2':
          order   => '62',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /usr/share/selinux/ -p wa -k MAC-policy',
        }
      }
      'debian': {
        concat::fragment { 'mac policy rule 1':
          order   => '61',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /etc/apparmor/ -p wa -k MAC-policy',
        }
        concat::fragment { 'mac policy rule 2':
          order   => '62',
          target  => $cis_security_hardening::rules::auditd_init::rules_file,
          content => '-w /etc/apparmor.d/ -p wa -k MAC-policy',
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

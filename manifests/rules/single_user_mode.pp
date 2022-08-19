# @summary 
#    Ensure authentication required for single user mode 
#
# Single user mode (rescue mode) is used for recovery when the system detects an issue during boot 
# or by manual selection from the bootloader.
#
# Rationale:
# Requiring authentication in single user mode (rescue mode) prevents an unauthorized user from 
# rebooting the system into single user to gain root privileges without credentials.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::single_user_mode':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::single_user_mode (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['osfamily'].downcase() {
      'redhat': {
        case $facts['operatingsystemmajrelease'] {
          '8': {
            file_line { 'su-rescue':
              path  => '/usr/lib/systemd/system/rescue.service',
              line  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue',
              match => '^ExecStart=',
            }
            file_line { 'su-emergency':
              path  => '/usr/lib/systemd/system/emergency.service',
              line  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency',
              match => '^ExecStart=',
            }
          }
          '7': {
            file_line { 'su-rescue':
              path  => '/usr/lib/systemd/system/rescue.service',
              line  => 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
              match => '^ExecStart=',
            }
            file_line { 'su-emergency':
              path  => '/usr/lib/systemd/system/emergency.service',
              line  => 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
              match => '^ExecStart=',
            }
          }
          default: {
            file_line { 'sulogin':
              path               => '/etc/sysconfig/init',
              line               => 'SINGLE=/sbin/sulogin',
              match              => '^SINGLE=',
              append_on_no_match => true,
            }
          }
        }
      }
      'suse': {
        file_line { 'modify resuce':
          ensure             => present,
          path               => '/usr/lib/systemd/system/rescue.service',
          match              => '^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell',
          line               => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescure',
          append_on_no_match => true,
        }

        file_line { 'modify emergency':
          ensure             => present,
          path               => '/usr/lib/systemd/system/emergency.service',
          match              => '^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell',
          line               => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency',
          append_on_no_match => true,
        }
      }
      default: {
        # Nothing to do yet
      }
    }
  }
}

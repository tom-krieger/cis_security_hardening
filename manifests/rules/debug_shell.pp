# @summary
#    Ensure the operating system is configured to mask the debug- shell systemd service
#
# The debug-shell systemd service must be disabled. 
#
# Rationale:
# The debug-shell requires no authentication and provides root privileges to anyone who has physical access to 
# the machine. While this feature is disabled by default, masking it adds an additional layer of assurance that 
# it will not be enabled via a dependency in systemd. This also prevents attackers with physical access from 
# trivially bypassing security on the machine through valid troubleshooting configurations and gaining root access 
# when the system is rebooted.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::debug_shell':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::debug_shell (
  Boolean $enforce = false,
) {
  if $enforce {
    exec { 'mask debug-shell':
      command => 'systemctl mask debug-shell.service',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test -z "$(systemctl status debug-shell.service | grep -i "Loaded: masked")"',
      notify  => Exec['systemd-daemon-reload'],
    }
  }
}

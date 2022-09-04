# @summary
#    Ensure SSH performs checks of home directory configuration files
#
# The operating system must be configured so that the SSH daemon performs strict mode checking of home directory configuration files.
#
# Rationale:
# If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_strict_modes':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_strict_modes (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-strictmodes':
      ensure             => present,
      path               => $path,
      line               => 'StrictModes yes',
      match              => '^StrictModes.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

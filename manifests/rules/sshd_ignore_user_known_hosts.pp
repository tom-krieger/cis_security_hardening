# @summary 
#    Ensure SSH IgnoreUserKnownHosts is enabled
#
# The operating system must be configured so that the SSH daemon does not allow authentication using known hosts authentication.
#
# Rationale:
# Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, 
# even in the event of misconfiguration elsewhere.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_ignore_user_known_hosts':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_ignore_user_known_hosts (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-ignore_user_known_hosts':
      ensure             => present,
      path               => $path,
      line               => 'IgnoreUserKnownHosts yes',
      match              => '^IgnoreUserKnownHosts.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

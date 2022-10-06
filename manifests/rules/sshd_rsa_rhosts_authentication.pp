# @summary
#    Ensure RSA rhosts authentication is not allowed
#
# The operating system must be configured so that the SSH daemon does not allow authentication using RSA rhosts 
# authentication. If the release is 7.4 or newer this requirement is Not Applicable.
# 
# Rationale:
# Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require 
# a password, even in the event of misconfiguration elsewhere.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_rsa_rhosts_authentication':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_rsa_rhosts_authentication (
  Boolean $enforce = false,
) {
  if $enforce and $facts['os']['release']['full'] < '7.4' {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-rhosts-rsa-login':
      ensure             => present,
      path               => $path,
      line               => 'RhostsRSAAuthentication no',
      match              => '^#?RhostsRSAAuthentication.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

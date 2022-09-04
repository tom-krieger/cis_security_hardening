# @summary
#    Ensure SSH does not permit GSSAPI
#
# The operating system must be configured so that the SSH daemon does not permit Generic Security Service Application 
# Program Interface (GSSAPI) authentication unless needed.
#
# Rationale:
# GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication 
# through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication 
# must be disabled unless needed.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_gssasi':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_gssapi (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-gssapi':
      ensure             => present,
      path               => $path,
      line               => 'GSSAPIAuthentication no',
      match              => '^GSSAPIAuthentication.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

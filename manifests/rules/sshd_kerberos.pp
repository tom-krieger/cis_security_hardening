# @summary
#    Ensure SSH does not permit Kerberos authentication
#
# The operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed.
#
# Rationale:
# Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface 
# (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos 
# implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To 
# reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for 
# systems not using this capability.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_kerberos':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_kerberos (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-kerberos':
      ensure             => present,
      path               => $path,
      line               => 'KerberosAuthentication no',
      match              => '^KerberosAuthentication.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

# @summary
#    Ensure SSH compressions setting is delayed
#
# The operating system must be configured so that the SSH daemon does not allow compression or only allows compression after 
# successful authentication.
#
# Rationale:
# If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could 
# result in compromise of the system from an unauthenticated connection, potentially with root privileges.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_compression':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_compression (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-compression':
      ensure             => present,
      path               => $path,
      line               => 'Compression delayed',
      match              => '^Compression.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

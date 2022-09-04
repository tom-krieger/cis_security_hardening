# @summary
#    Ensure SSH Protocol is set to 2
#
# The Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol.
#
# Rationale:
# SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of 
# the SSH daemon could provide immediate root access to the system.
#
# Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_protocol':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_protocol (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-protocol':
      ensure             => present,
      path               => $path,
      line               => 'Protocol 2',
      match              => '^Protocol.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

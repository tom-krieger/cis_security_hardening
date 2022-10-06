# @summary
#    Ensure SSH uses privilege separation
#
# The operating system must be configured so that the SSH daemon uses privilege separation.
#
# Rationale:
# SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would 
# decrease the impact of software vulnerabilities in the unprivileged section.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_priv_separation':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_priv_separation (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-privseparation':
      ensure             => present,
      path               => $path,
      line               => 'UsePrivilegeSeparation sandbox',
      match              => '^#?UsePrivilegeSeparation.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

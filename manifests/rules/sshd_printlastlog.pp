# @summary 
#    Ensure Printlastlog is enabled
#
# The operating system must display the date and time of the last successful account logon upon an SSH logon.
#
# Rationale:
# Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition 
# and reporting of unauthorized account use.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::sshd_printlastlog':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_printlastlog (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-printlastlog':
      ensure             => present,
      path               => $path,
      line               => 'PrintLastLog yes',
      match              => '^PrintLastLog.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

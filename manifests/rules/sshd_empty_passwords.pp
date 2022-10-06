# @summary 
#    Ensure SSH PermitEmptyPasswords is disabled 
#
# The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with 
# empty password strings.
#
# Rationale:
# Disallowing remote shell access to accounts that have an empty password reduces the probability 
# of unauthorized access to the system
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_empty_passwords':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_empty_passwords (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-empty-passwords':
      ensure => present,
      path   => $path,
      line   => 'PermitEmptyPasswords no',
      match  => '^#?PermitEmptyPasswords.*',
      notify => Exec['reload-sshd'],
    }
  }
}

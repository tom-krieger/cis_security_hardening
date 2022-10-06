# @summary 
#    Ensure SSH PermitUserEnvironment is disabled 
#
# The PermitUserEnvironment option allows users to present environment options to the ssh daemon.
#
# Rationale:
# Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to 
# bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_user_environment':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_user_environment (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-user-environment':
      ensure => present,
      path   => $path,
      line   => 'PermitUserEnvironment no',
      match  => '^#?PermitUserEnvironment.*',
      notify => Exec['reload-sshd'],
    }
  }
}

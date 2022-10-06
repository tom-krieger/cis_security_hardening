# @summary 
#    Ensure SSH LoginGraceTime is set to one minute or less 
#
# The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server. 
# The longer the Grace period is the more open unauthenticated connections can exist. Like other session 
# controls in this session the Grace Period should be limited to appropriate organizational limits to 
# ensure the service is available for needed access.
# Rationale:
# Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks 
# to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended 
# setting is 60 seconds (1 Minute), set the number based on site policy.
#
# @param enforce
#    Enforce the rule
#
# @param login_grace_time
#    Time allowed for successful authentication
#
# @example
#   class { 'cis_security_hardening::rules::sshd_login_gracetime':
#       enforce => true,
#       login_grace_time => 50,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_login_gracetime (
  Boolean $enforce          = false,
  Integer $login_grace_time = 60,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-login-gracetime':
      ensure => present,
      path   => $path,
      line   => "LoginGraceTime ${login_grace_time}",
      match  => '^#?LoginGraceTime.*',
      notify => Exec['reload-sshd'],
    }
  }
}

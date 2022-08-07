# @summary 
#    Ensure SSH MaxAuthTries is set to 4 or less (Automated)
#
# The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. 
# When the login failure count reaches half the number, error messages will be written to the syslog file 
# detailing the login failure.
#
# Rationale:
# Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to 
# the SSH server. While the recommended setting is 4, set the number based on site policy.
#
# @param enforce
#    Enforce the rule 
#
# @param max_auth_tries
#    Maximun number of failed authentication attempts
#
# @example
#   class { 'cis_security_hardening::rules::sshd_max_auth_tries':
#       enforce => true,
#       max_auth_tries => 4,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_max_auth_tries (
  Boolean $enforce        = false,
  Integer $max_auth_tries = 4,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-max-auth-tries':
      ensure => present,
      path   => $path,
      line   => "MaxAuthTries ${max_auth_tries}",
      match  => '^MaxAuthTries.*',
      notify => Exec['reload-sshd'],
    }
  }
}

# @summary 
#    Ensure SSH MaxStartups is configured 
#
# The MaxStartups parameter specifies the maximum number of concurrent unauthenticated connections 
# to the SSH daemon.
#
# Rationale:
# To protect a system from denial of service due to a large number of pending authentication connection 
# attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and 
# prevent overwhelming the daemon.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_max_startups':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_max_startups (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['os']['name'] == 'SLES' and $facts['os']['release']['major'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-max-startups':
      ensure             => present,
      path               => $path,
      line               => 'MaxStartups 10:30:60',
      match              => '^#?MaxStartups.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

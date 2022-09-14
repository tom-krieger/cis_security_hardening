# @summary 
#    Ensure SSH MaxSessions is set to 4 or less 
#
# The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection.
#
# Rationale:
# To protect a system from denial of service due to a large number of concurrent sessions, use the rate 
# limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sshd_max_sessions':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_max_sessions (
  Boolean $enforce = false,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-max-sessions':
      ensure             => present,
      path               => $path,
      line               => 'maxsessions 4',
      match              => '^#?maxsessions.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  }
}

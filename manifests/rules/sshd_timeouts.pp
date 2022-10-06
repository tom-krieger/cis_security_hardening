# @summary 
#    Ensure SSH Idle Timeout Interval is configured 
#
# The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions. When 
# the ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length 
# of time are terminated. When the ClientAliveCountMax variable is set, sshd will send client alive 
# messages at every ClientAliveInterval interval. When the number of consecutive client alive messages 
# are sent with no response from the client, the ssh session is terminated. For example, if the 
# ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session 
# will be terminated after 45 seconds of idle time.
#
# Rationale:
# Having no timeout value associated with a connection could allow an unauthorized user access to another user's 
# ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value at 
# least reduces the risk of this happening.
#
# While the recommended setting is 300 seconds (5 minutes), set this timeout value based on site policy. The 
# recommended setting for ClientAliveCountMax is 0. In this case, the client session will be terminated after 
# 5 minutes of idle time and no keepalive messages will be sent.
#
# @param enforce
#    Enforce the rule 
#
# @param client_alive_interval
#    The client alive imterval
#
# @param client_alive_count_max
#    The client alive cout max
#
# @example
#   class { 'cis_security_hardening::rules::sshd_timeouts':
#       enforce => true,
#       client_alive_interval => 200,
#       client_alive_count_max => 0,
#   }
#
# @api private
class cis_security_hardening::rules::sshd_timeouts (
  Boolean $enforce                = false,
  Integer $client_alive_interval  = 300,
  Integer $client_alive_count_max = 0,
) {
  if $enforce {
    $path = ($facts['operatingsystem'] == 'SLES' and $facts['operatingsystemmajrelease'] == '12') ? {
      true    => '/usr/etc/ssh/sshd_config',
      default => '/etc/ssh/sshd_config',
    }
    file_line { 'sshd-timeouts':
      ensure => present,
      path   => $path,
      line   => "ClientAliveInterval ${client_alive_interval}",
      match  => '^#?ClientAliveInterval.*',
      notify => Exec['reload-sshd'],
    }

    file_line { 'sshd-timeouts-2':
      ensure => present,
      path   => $path,
      line   => "ClientAliveCountMax ${client_alive_count_max}",
      match  => '^#?ClientAliveCountMax.*',
      notify => Exec['reload-sshd'],
    }
  }
}

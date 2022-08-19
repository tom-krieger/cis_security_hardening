# @summary 
#    Ensure rsyslog is configured to send logs to a remote log host 
#
# The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or 
# to receive messages from remote hosts, reducing administrative overhead.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access 
# on the local system, they could tamper with or remove log data that is stored on the local system
#
# @param enforce
#    Enforce the rule
#
# @param remote_log_host
#    Remote syslog server to send logs to
#
# @example
#   class { 'cis_security_hardening::rules::rsyslog_remote_logs':
#       enforce => true,
#       remote_log_host => '10.10.54.2',
#   }
#
# @api private
class cis_security_hardening::rules::rsyslog_remote_logs (
  Boolean $enforce        = false,
  String $remote_log_host = '',
) {
  if $enforce and ($remote_log_host != '') {
    file_line { 'rsyslog-remote-log-host':
      ensure  => present,
      path    => '/etc/rsyslog.conf',
      line    => "*.* @@${remote_log_host}",
      match   => '^\*\.\* \@\@.*',
      notify  => Exec['reload-rsyslog'],
      require => Package['rsyslog'],
    }
  }
}

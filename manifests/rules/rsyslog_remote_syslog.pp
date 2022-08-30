# @summary 
#    Ensure remote rsyslog messages are only accepted on designated log hosts. 
#
# By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog 
# to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs 
# rsyslogd to listen on the specified TCP port.
#
# Rationale:
# The guidance in the section ensures that remote log hosts are configured to only accept rsyslog data from hosts 
# within the specified domain and that those systems that are not designed to be log hosts do not accept any remote 
# rsyslog messages. This provides protection from spoofed log data and ensures that system administrators are 
# reviewing reasonably complete syslog data in a central location.
#
# @param enforce
#    Enforce the rule
#
# @param is_loghost
#    Flag if host is a remote log destination for rsyslog
#
# @example
#   class { 'cis_security_hardening::rules::rsyslog_remote_syslog':
#       enforce => true,
#       is_loghost => false,
#   }
#
# @api public
class cis_security_hardening::rules::rsyslog_remote_syslog (
  Boolean $enforce    = false,
  Boolean $is_loghost = false,
) {
  if $enforce {
    if($is_loghost) {
      file_line { 'rsyslog.conf add ModLoad':
        ensure             => present,
        path               => '/etc/rsyslog.conf',
        line               => '$ModLoad imtcp',
        match              => '^#.*\$ModLoad.*imtcp',
        append_on_no_match => true,
        require            => Package['rsyslog'],
      }

      file_line { 'rsyslog.conf add InputTCPServerRun':
        ensure  => present,
        path    => '/etc/rsyslog.conf',
        line    => '$InputTCPServerRun 514',
        match   => '\$InputTCPServerRun',
        require => Package['rsyslog'],
      }
    } else {
      file_line { 'rsyslog.conf remove ModLoad':
        ensure  => present,
        path    => '/etc/rsyslog.conf',
        line    => '# $ModLoad imtcp',
        match   => '^\$ModLoad.*imtcp',
        require => Package['rsyslog'],
      }

      file_line { 'rsyslog.conf remove InputTCPServerRun':
        ensure  => present,
        path    => '/etc/rsyslog.conf',
        line    => '#$InputTCPServerRun 514',
        match   => '\$InputTCPServerRun',
        require => Package['rsyslog'],
      }
    }
  }
}

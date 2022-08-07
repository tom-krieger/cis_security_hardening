# @summary 
#    Ensure rsyslog default file permissions configured (Automated)
#
# rsyslog will create logfiles that do not already exist on the system. This setting controls what permissions 
# will be applied to these newly created files.
#
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure that sensitive data is 
# archived and protected.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::rsyslog_default_file_perms':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rsyslog_default_file_perms (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'rsyslog-filepermissions':
      ensure  => present,
      path    => '/etc/rsyslog.conf',
      line    => '$FileCreateMode 0640',
      match   => '^\$FileCreateMode.*',
      notify  => Exec['reload-rsyslog'],
      require => Package['rsyslog'],
    }
    if(!defined(File['/etc/rsyslog.d/'])) {
      file { '/etc/rsyslog.d/':
        ensure  => directory,
        recurse => true,
        mode    => '0640',
        require => Package['rsyslog'],
      }
    }
  }
}

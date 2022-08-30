# @summary 
#    Ensure logging is configured 
#
# The /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files specifies rules for logging and which files are to be used to 
# log certain classes of messages.
# 
# Rationale:
# A great deal of important security-related information is sent via rsyslog (e.g., successful and failed su attempts, f
# ailed login attempts, root login attempts, etc.).
#
# @param enforce
#    Enforce the rule
#
# @param log_config
#    Logfiles to configure
#
# @example
#   class { 'cis_security_hardening::rules::rsyslog_logging':
#       enforce => true,
#       log_config => {
#         '*.emerg' => ':omusrmsg:*',
#       }
#   }
#
# @api public
class cis_security_hardening::rules::rsyslog_logging (
  Boolean $enforce = false,
  Hash $log_config = {},
) {
  if $enforce {
    $log_config.each | $config, $data | {
      $src = $data['src']
      $dst = $data['dst']
      file { "/etc/rsyslog.d/${config}.conf":
        ensure  => file,
        content => "${src} ${dst}",
        notify  => Exec['reload-rsyslog'],
        require => Package['rsyslog'],
      }
    }
  }
}

# @summary 
#    Ensure journald is configured to write logfiles to persistent disk (Automated)
#
# Data from journald may be stored in volatile memory or persisted locally on the server. Logs in memory 
# will be lost upon a system reboot. By persisting logs to local disk on the server they are protected 
# from loss.
# 
# Note: The main configuration file /etc/systemd/journald.conf is read before any of the custom *.conf 
# files. If there are custom configs present, they override the main configuration parameters
#
# Rationale:
# Writing log data to disk will provide the ability to forensically reconstruct events which may have impacted 
# the operations or security of a system even after a system crash or reboot.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::journald_persistent':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::journald_persistent (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'journald write persistent':
      ensure             => present,
      path               => '/etc/systemd/journald.conf',
      line               => 'Storage=persistent',
      match              => '^Storage=',
      append_on_no_match => true,
      require            => Package['rsyslog'],
    }
  }
}

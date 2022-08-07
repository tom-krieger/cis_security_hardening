# @summary 
#    Ensure journald is configured to compress large log files (Automated)
#
# The journald system includes the capability of compressing overly large files to avoid filling up 
# the system with logs or making the logs unmanageably large.
#
# Note: The main configuration file /etc/systemd/journald.conf is read before any of the custom *.conf files. 
# If there are custom configs present, they override the main configuration parameters.
#
# Rationale:
# Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability. Compressing logs 
# prior to write can prevent sudden, unexpected filesystem impacts.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::journald_compress':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::journald_compress (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'journald compress':
      ensure             => present,
      path               => '/etc/systemd/journald.conf',
      line               => 'Compress=yes',
      match              => '^Compress=',
      append_on_no_match => true,
      require            => Package['rsyslog'],
    }
  }
}

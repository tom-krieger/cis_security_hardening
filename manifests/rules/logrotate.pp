# @summary 
#    Ensure logrotate is configured 
#
# The system includes the capability of rotating log files regularly to avoid filling up the 
# system with logs or making the logs unmanageable large. The file /etc/logrotate.d/syslog is 
# the configuration file used to rotate log files created by syslog or rsyslog.
#
# Rationale:
# By keeping the log files smaller and more manageable, a system administrator can easily archive these files 
# to another system and spend less time looking through inordinately large log files.
#
# @param enforce
#    Enforce the rule
# @param dateext
#    Use date extension for rotated files.
# @param compress
#    Compress rotated files.
# @param delaycompress
#    Delay compression of rotated files.
# @param rotate
#    Number of rotations to keep.
# @param rotate_every
#    Frequency of rotation (e.g., 'daily', 'weekly').
# @param ifempty
#    Rotate the log file even if it is empty.
# @param su
#    Use su directive for logrotate.
# @param su_user
#    User for logrotate.
# @param su_group
#    Group for logrotate.
#
# @example
#   class { 'cis_security_hardening::rules::logrotate':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::logrotate (
  Boolean $enforce       = false,
  Boolean $dateext       = true,
  Boolean $compress      = true,
  Boolean $delaycompress = false,
  Integer $rotate        = 7,
  String $rotate_every   = 'week',
  Boolean $ifempty       = true,
  Boolean $su            = false,
  String $su_user        = 'root',
  String $su_group       = 'syslog',
) {
  if $enforce {
    class { 'logrotate':
      create_base_rules => false,
      config            => {
        dateext       => $dateext,
        compress      => $compress,
        delaycompress => $delaycompress,
        rotate        => $rotate,
        rotate_every  => $rotate_every,
        ifempty       => $ifempty,
        su            => $su,
        su_user       => $su_user,
        su_group      => $su_group,
      },
    }
  }
}

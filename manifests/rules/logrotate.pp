# @summary 
#    Ensure logrotate is configured (Manual)
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
  Boolean $enforce = false,
  String $su_user  = 'root',
  String $su_group = 'syslog',
) {
  if $enforce {
    class { 'logrotate':
      create_base_rules => false,
      config            => {
        dateext      => true,
        compress     => true,
        rotate       => 7,
        rotate_every => 'week',
        ifempty      => true,
      },
    }
  }
}

# @summary 
#    Ensure journald is configured to send logs to rsyslog (Automated)
#
# Data from journald may be stored in volatile memory or persisted locally on the server. Utilities #
# exist to accept remote export of journald logs, however, use of the rsyslog service provides a consistent 
# means of log collection and export.
#
# Notes:
#      * This recommendation assumes that recommendation 4.2.1.5, "Ensure rsyslog is configured to send logs 
#        to a remote log host" has been implemented.
#      * The main configuration file /etc/systemd/journald.conf is read before any of the custom *.conf files. If 
#        there are custom configs present, they override the main configuration parameters
#      * As noted in the journald man pages: journald logs may be exported to rsyslog either through the process 
#        mentioned here, or through a facility like systemd- journald.service. There are trade-offs involved in each 
#        implementation, where ForwardToSyslog will immediately capture all events (and forward to an external log 
#        server, if properly configured), but may not capture all boot-up activities. Mechanisms such as 
#        systemd-journald.service, on the other hand, will record bootup events, but may delay sending the information 
#        to rsyslog, leading to the potential for log manipulation prior to export. Be aware of the limitations of all 
#        tools employed to secure a system.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the 
# local system, they could tamper with or remove log data that is stored on the local system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::journald_rsyslog':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::journald_rsyslog (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'journald to rsyslog':
      ensure             => present,
      path               => '/etc/systemd/journald.conf',
      line               => 'ForwardToSyslog=yes',
      match              => '^ForwardToSyslog=',
      append_on_no_match => true,
      require            => Package['rsyslog'],
    }
  }
}

# @summary 
#    Ensure rsyslog or syslog-ng is installed (Automated)
#
# The rsyslog and syslog-ng software are recommended replacements to the original syslogd daemon which 
# provide improvements over syslogd , such as connection-oriented (i.e. TCP) transmission of logs, the 
# option to log to database formats, and the encryption of log data en route to a central logging server.
#
# Rationale:
# The security enhancements of rsyslog and syslog-ng such as connection-oriented (i.e. TCP) transmission of 
# logs, the option to log to database formats, and the encryption of log data en route to a central logging 
# server) justify installing and configuring the package.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class 'cis_security_hardening::rules::rsyslog_installed' {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rsyslog_installed (
  Boolean $enforce = false,
) {
  if $enforce {
    ensure_packages(['rsyslog'], {
        ensure => installed,
    })
  }
}

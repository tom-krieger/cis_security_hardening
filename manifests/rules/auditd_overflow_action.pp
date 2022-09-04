# @summary
#    Ensure action is taken when audisp-remote buffer is full
#
# The operating system must take appropriate action when the audisp-remote buffer is full.
#
# Rationale:
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
#
# Off-loading is a common process in information systems with limited audit storage capacity.
#
# When the remote buffer is full, audit logs will not be collected and sent to the central log server.
#
# @param enforce
#    Enforce the rule.
#
# @param action
#    The action to be taken.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_overflow_action':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_overflow_action (
  Boolean $enforce                       = false,
  Enum['syslog','single','halt'] $action = 'syslog',
) {
  if $enforce {
    file_line { 'overflow-action':
      ensure => present,
      path   => '/etc/audisp/audispd.conf',
      match  => '^overflow_action =',
      line   => "overflow_action = ${action}",
      notify => Service['auditd'],
    }
  }
}

# @summary
#    Ensure off-loaded audit logs are labeled.
#
# The operating system must label all off-loaded audit logs before sending them to the central log server.
#
# Rationale:
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
#
# Off-loading is a common process in information systems with limited audit storage capacity.
#
# When audit logs are not labeled before they are sent to a central log server, the audit data will not be 
# able to be analyzed and tied back to the correct system.
#
# @param enforce
#    Enforce the rule.
# @param format
#    The name format.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_remote_labled':
#     enforce => true,
#     format => 'hostname',
#   }
#
# @api private
class cis_security_hardening::rules::auditd_remote_labeled (
  Boolean $enforce                         = false,
  Enum['hostname','fqd','numeric'] $format = 'hostname',
) {
  if $enforce {
    file_line { 'name-format':
      ensure => present,
      path   => '/etc/audisp/audispd.conf',
      match  => '^name_format =',
      line   => "name_format = ${format}",
      notify => Service['auditd'],
    }
  }
}

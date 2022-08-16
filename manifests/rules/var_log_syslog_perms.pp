# @summary 
#    Ensure /var/log/syslog is group-owned by adm, owned by syslog and has permissions 0640
#
# The operating system must configure the /var/log/syslog file to be group-owned by adm.
#
# Rationale:
# Only authorized personnel should be aware of errors and the details of the errors. Error messages 
# are an indicator of an organization's operational state or can identify the operating system or 
# platform. Additionally, Personally Identifiable Information (PII) and operational information must 
# not be revealed through error messages to unauthorized personnel or their designated representatives.
#
# The structure and content of error messages must be carefully considered by the organization and development 
# team. The extent to which the information system is able to identify and handle error conditions is guided 
# by organizational policy and operational requirements.
#
# @param enforce
#    Enforce the rule.
# @param user
#    The user owning the file.
# @param group
#    The group owning the file.
# @param mode
#    The access permissions.
#
# @example
#   class { 'cis_security_hardening::rules::var_log_syslog_perms':
#     enforce => true,
#     user => 'syslog',
#     group => 'adm',
#     mode => '0640',
#   }
#
# @api private
class cis_security_hardening::rules::var_log_syslog_perms (
  Boolean $enforce = false,
  String $user     = 'syslog',
  String $group    = 'adm',
  String $mode     = '0640',
) {
  if $enforce {
    file { '/var/log/syslog':
      ensure => file,
      owner  => $user,
      group  => $group,
      mode   => $mode,
    }
  }
}

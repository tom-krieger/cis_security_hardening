# @summary 
#    Ensure audit configuration files are 0640 or more restrictive and confibgure user and group
#
# The operating system must be configured so that audit configuration files are not write- accessible by unauthorized users.
#
# The operating system must permit only authorized accounts to own the audit configuration files.
#
# The operating system must permit only authorized groups to own the audit configuration files.
#
# Rationale:
# Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel 
# may be able to prevent the auditing of critical events.
#
# Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also 
# make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those 
# responsible for one.
#
# Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel 
# may be able to prevent the auditing of critical events.
#
# Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make 
# it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible 
# for one.
#
# Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel 
# may be able to prevent the auditing of critical events.
# 
# Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make 
# it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible 
# for one.
#
# @param enforce
#    Enforce the rule.
# @param user
#    User owning the files.
# @param group
#    Group owning the files.
# @param mode
#    File access permissions.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_conf_perms':
#     enforce => true,
#     user => 'root',
#     group => 'root',
#     mode => '0640',
#   }
#
# @api private
class cis_security_hardening::rules::auditd_conf_perms (
  Boolean $enforce = false,
  String $user     = 'root',
  String $group    = 'root',
  String $mode     = '0640',
) {
  if $enforce {
    if
        has_key($facts, 'cis_security_hardening') and
        has_key($facts['cis_security_hardening'], 'auditd') and
        has_key($facts['cis_security_hardening']['auditd'], 'config_files')
    {
      $facts['cis_security_hardening']['auditd']['config_files'].each |$conf| {
        file { $conf:
          ensure => file,
          owner  => $user,
          group  => $group,
          mode   => $mode,
        }
      }
    }
  }
}

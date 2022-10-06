# @summary
#    Ensure the operating system's audit daemon is configured to resolve audit information before writing to disk
#
# The operating system must resolve audit information before writing to disk. 
#
# Rationale:
# Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, 
# it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.
#
# Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and 
# destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and 
# access control or flow control rules invoked.
#
# Enriched logging aids in making sense of who, what, and when events occur on a system. Without this, determining root 
# cause of an event will be much more difficult.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_log_format':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_log_format (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'auditd_log_format':
      line               => 'log_format = ENRICHED',
      path               => '/etc/audit/auditd.conf',
      match              => '^log_format',
      append_on_no_match => true,
    }
  }
}

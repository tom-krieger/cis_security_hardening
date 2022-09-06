# @summary
#    Ensure the operating system's audit daemon is configured to include local events
#
# The audit system must audit local events. 
#
# Rationale:
# Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, 
# it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.
#
# Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and 
# destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and 
# access control or flow control rules invoked.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_local_events':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_local_events (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'auditd_local_events':
      line               => 'local_events = yes',
      path               => '/etc/audit/auditd.conf',
      match              => '^local_events',
      append_on_no_match => true,
    }
  }
}

# @summary
#    Ensure the operating system enables Linux audit logging of the USBGuard daemon
#
# The operating system must enable Linux audit logging for the USBGuard daemon. 
#
# Rationale:
# Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate 
# the events relating to an incident or identify those responsible for one.
#
# If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some 
# audit systems also maintain state information only available if auditing is enabled before a given process is created.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# The list of audited events is the set of events for which audits are to be generated. This set of events is typically 
# a subset of the list of all events for which the system is capable of generating audit records.
#
# DoD has defined the list of events for which the operating system will provide an audit record generation capability 
# as the following:
# 1. Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or 
#    categories of information (e.g., classification levels);
# 2. Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, 
#   starting and ending time for user access to the system, concurrent logons from different workstations, successful and 
#   unsuccessful accesses to objects, all program initiations, and all direct access to the information system;
# 3. All account creations, modifications, disabling, and terminations; and
# 4. All kernel module load, unload, and restart actions.
#
# Satisfies: SRG-OS-000062-GPOS-00031, SRG-OS-000471-GPOS-00215
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_usbguard':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_usbguard (
  Boolean $enforce = false,
) {
  if $enforce {
    file_line { 'auditd_usbguard':
      line  => 'AuditBackend=LinuxAudit',
      path  => '/etc/usbguard/usbguard-daemon.conf',
      match => '^AuditBackend=',
    }
  }
}

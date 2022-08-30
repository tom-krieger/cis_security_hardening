# @summary 
#    Ensure nonlocal administrative access events are collected
#
# The operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions 
# and other system-level access.
#
# Rationale:
# If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for 
# assessing and investigating attacks would not be available.
#
# This requirement addresses auditing-related issues associated with maintenance tools used specifically for 
# diagnostic and repair actions on organizational information systems.
#
# Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through 
# a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic 
# activities are those activities carried out by individuals physically present at the information system or information 
# system component and not communicating across a network connection.
#
# This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover 
# hardware/software components that may support information system maintenance, yet are a part of the system, for example, 
# the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an 
# Ethernet switch.
#
# Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215
#
# @param enforce 
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_nonlocal_admin_access':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_nonlocal_admin_access (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch nonlocal_admin_access command rule 1':
      order   => '193',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /var/log/sudo.log -p wa -k maintenance',
    }
  }
}

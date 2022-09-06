# @summary
#    Ensure the operating system takes action when allocated audit record storage volume reaches 75 percent of the repository 
#    maximum audit record storage capacity
#
# The operating system must take action when allocated audit record storage volume reaches 75 percent of the repository maximum 
# audit record storage capacity.
#
# Rationale:
# If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan 
# for audit record storage capacity expansion.
#
# @param enforce
#    Enforce the rule.
# @param space_left
#    Percent of space left.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_space_left':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_space_left (
  Boolean $enforce = false,
  Integer $space_left = 25,
) {
  if $enforce {
    file_line { 'auditd_space_left':
      line               => "space_left = ${space_left}%",
      path               => '/etc/audit/auditd.conf',
      match              => '^space_left',
      append_on_no_match => true,
    }
  }
}

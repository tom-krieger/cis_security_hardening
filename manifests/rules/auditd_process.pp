# @summary 
#    Ensure auditing for processes that start prior to auditd is enabled 
#
# Configure grub so that processes that are capable of being audited can be audited even if they start up 
# prior to auditd startup.
#
# Rationale:
# Audit events need to be captured on processes that start up prior to auditd, so that potential malicious 
# activity cannot go undetected.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::sec_auditd_process':
#             enforce => true,
#   }
#
# @example
#   include cis_security_hardening::rules::auditd_process
#
# @api private
class cis_security_hardening::rules::auditd_process (
  Boolean $enforce = false,
) {
  if $enforce {
    kernel_parameter { 'audit':
      ensure => present,
      value  => '1',
    }
  }
}

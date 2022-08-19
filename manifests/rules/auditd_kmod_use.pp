# @summary 
#    Ensure successful and unsuccessful attempts to use the kmod command are recorded
#
# The operating system must generate audit records when successful/unsuccessful attempts to use the kmod command.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it 
# would be difficult to establish, correlate, and investigate the events relating to an incident or identify 
# those responsible for one.
#
# Audit records can be generated from various components within the information system (e.g., module or 
# policy filter).
#
# @param enforce
#    Enforce the rule. 
#
# @example
#   class { 'cis_security_hardening::rules::auditd_kmod_use':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_kmod_use (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch kmod command rule 1':
      order   => '194',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-w /bin/kmod -p x -k modules',
    }
  }
}

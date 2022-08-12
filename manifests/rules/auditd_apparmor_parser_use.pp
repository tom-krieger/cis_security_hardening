# @summary 
#    Ensure successful and unsuccessful attempts to use the apparmor_parser command are recorded
#
# he operating system must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it would 
# be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible 
# for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_apparmor_parser_use':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_apparmor_parser_use (
  Boolean $enforce = false,
) {
  if $enforce {
    concat::fragment { 'watch apparmor_parser command rule 1':
      order   => '177',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => '-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng',
    }
  }
}

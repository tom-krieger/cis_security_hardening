# @summary
#    Ensure successful and unsuccessful attempts to use the chsh command are recorded
#
# The operating system must generate audit records for successful/unsuccessful uses of the chsh command.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, 
# it would be difficult to establish, correlate, and investigate the events relating to an incident or identify 
# those responsible for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_chsh_use':
#     enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::auditd_chsh_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch chsh command rule 1':
      order   => '174',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=${uid} -F auid!=4294967295 -k priv_cmd",
    }
  }
}

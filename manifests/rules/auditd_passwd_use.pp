# @summary 
#    Ensure successful and unsuccessful attempts to use the passwd command are recorded
#
# The operating system must generate audit records for successful/unsuccessful uses of the passwd command
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
#   class  'cis_security_hardening::rules::auditd_passwd_use':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_passwd_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch passwd command rule 1':
      order   => '180',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=${uid} -F auid!=4294967295 -k privileged-passwd",
    }
  }
}

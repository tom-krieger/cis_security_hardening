# @summary
#    Ensure audit of postdrop command
#
# The operating system must audit all uses of the postdrop command.
#
# Rationale:
# Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
#
# At a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization 
# must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_postdrop':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_postdrop (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch postdrop rule 1':
      order   => '208',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F path=/usr/sbin/postdrop -F auid>=${uid} -F auid!=4294967295 - k privileged-postfix",
    }
  }
}

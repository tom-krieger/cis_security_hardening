# @summary
#    Ensure audit the umount command
#
# The operating system must audit all uses of the umount command.
#
# Rationale:
# Reconstruction of harmful events or forensic analysis is not possible if audit records do not 
# contain enough information.
#
# At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization 
# must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_umount':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_umount (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch umount rule 1':
      order   => '207',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F path=/usr/bin/umount -F auid>=${uid} -F auid!=4294967295 -k privileged-mount",
    }
  }
}

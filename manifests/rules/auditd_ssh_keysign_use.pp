# @summary 
#    Ensure successful and unsuccessful uses of the ssh-keysign command are collected
#
# The operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
#
# Rationale:
# Without generating audit records that are specific to the security and mission needs of the organization, it 
# would be difficult to establish, correlate, and investigate the events relating to an incident or identify 
# those responsible for one.
#
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::auditd_ssh_keysign_use':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_ssh_keysign_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    $rule1 = $facts['os']['name'].downcase() ? {
      'redhat' => "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=${uid} -F auid!=4294967295 -k privileged-ssh",
      default  => "-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=${uid} -F auid!=4294967295 -k privileged-ssh",
    }
    concat::fragment { 'watch ssh-keysign command rule 1':
      order   => '143',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => $rule1,
    }
  }
}

# @summary 
#    Ensure successful and unsuccessful attempts to use the usermod command are recorded
#
# The operating system must generate audit records for successful/unsuccessful uses of the usermod command.
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
#   class { 'cis_security_hardening::rules::auditd_usermod_use':
#     enforce =A true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_usermod_use (
  Boolean $enforce = false,
) {
  if $enforce {
    $auid = $facts['os']['name'].downcase() ? {
      'rocky'     => 'unset',
      'almalinux' => 'unset',
      'debian'    => 'unset',
      default     => '4294967295',
    }
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch usermod command rule 1':
      order   => '184',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${uid} -F auid!=${auid} -k privileged-usermod",
    }
  }
}

# @summary
#    Ensure audit of the setsebool command.
#
# The operating system must audit all uses of the setsebool command.
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
#   class { 'cis_security_hardening::rules::auditd_setsebool':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_setsebool (
  Boolean $enforce = false,
) {
  if $enforce {
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    concat::fragment { 'watch setsebool rule 1':
      order   => '213',
      target  => $cis_security_hardening::rules::auditd_init::rules_file,
      content => "-a always,exit -F path=/usr/sbin/setsebool -F auid>=${uid} -F auid!=4294967295 -k privileged-priv_change",
    }
  }
}

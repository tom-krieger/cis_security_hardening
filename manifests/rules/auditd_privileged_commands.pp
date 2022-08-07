# @summary 
#    Ensure use of privileged commands is collected (Automated)
#
# Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to 
# determine if unprivileged users are running these commands.
#
# Rationale:
# Execution of privileged commands by non-privileged users could be an indication of someone trying 
# to gain unauthorized access to the system.
#
# @param enforce
#    Sets rule enforcement. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @example
#   class { 'cis_security_hardening::rules::auditd_privileged_commands':
#             enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::auditd_privileged_commands (
  Boolean $enforce                 = false,
) {
  if $enforce {
    $privlist = fact('cis_security_hardening.auditd.priv-cmds-list')
    unless $privlist == undef {
      concat::fragment { 'priv. commands rules':
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => epp('cis_security_hardening/rules/common/auditd_priv_commands.epp', {
            data => $privlist
        }),
        order   => '250',
      }
    }
  }
}

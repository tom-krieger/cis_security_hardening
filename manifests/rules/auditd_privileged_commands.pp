# @summary 
#    Ensure use of privileged commands is collected 
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
    # $dir = dirname($cis_security_hardening::rules::auditd_init::rules_file)
    # $rules_file = "${dir}/cis_security_hardening_priv_cmds.rules"
    $privlist = fact('cis_security_hardening.auditd.priv-cmds-list')
    $uid = fact('cis_security_hardening.auditd.uid_min') ? {
      undef   => '1000',
      default => fact('cis_security_hardening.auditd.uid_min'),
    }
    $auid = $facts['os']['name'].downcase() ? {
      'rocky'     => 'unset',
      'almalinux' => 'unset',
      default     => '4294967295',
    }

    unless $privlist == undef {
      concat::fragment { 'priv. commands rules':
        target  => $cis_security_hardening::rules::auditd_init::rules_file,
        content => epp('cis_security_hardening/rules/common/auditd_priv_commands.epp', {
            data => $privlist,
            uid  => $uid,
            auid => $auid
        }),
        order   => '350',
      }
    }
  }
}

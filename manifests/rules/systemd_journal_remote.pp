# @summary 
#    Ensure systemd-journal-remote is installed
#
# Journald (via systemd-journal-remote) supports the ability to send log events it gathers to a remote 
# log host or to receive messages from remote hosts, thus enabling centralised log management.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root 
# access on the local system, they could tamper with or remove log data that is stored on the local system.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::systemd_journal_remote':
#     enforce => true,
#   }
# 
# @api private
class cis_security_hardening::rules::systemd_journal_remote (
  Boolean $enforce = false,
) {
  if $enforce {
    package { 'systemd-journal-remote':
      ensure => installed,
    }
  }
}

# @summary A
#    Ensure systemd-journal-remote is enabled 
#
# Journald (via systemd-journal-remote) supports the ability to send log events it gathers to a remote log host 
# or to receive messages from remote hosts, thus enabling centralised log management.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on 
# the local system, they could tamper with or remove log data that is stored on the local system.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::systemd_journal_remote_service':
#     enforce => true,
#   }
# 
# @api private
class cis_security_hardening::rules::systemd_journal_remote_service (
  Boolean $enforce = false,
) {
  if $enforce {
    service { 'systemd-journal-upload':
      ensure => running,
      enable => true,
    }
  }
}

# @summary
#   Ensure journald is not configured to recieve logs from a remote client (Automated)
#
# Journald supports the ability to receive messages from remote hosts, thus acting as a log server. Clients should not 
# receive data from other hosts.
#
# NOTE:
# * The same package, systemd-journal-remote, is used for both sending logs to remote hosts and receiving incoming logs.
# * With regards to receiving logs, there are two services; systemd-journal- remote.socket and systemd-journal-remote.service.
#
# Rationale:
# If a client is configured to also receive data, thus turning it into a server, the client system is acting outside it's 
# operational boundary.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::systemd_journal_remote_receive':
#     enforce => true,
#   }
# 
# @api private
class cis_security_hardening::rules::systemd_journal_remote_receive (
  Boolean $enforce = false,
) {
  if enforce {
    service { 'systemd-journal-remote.socket':
      ensure => stopped,
      enable => false,
    }
  }
}

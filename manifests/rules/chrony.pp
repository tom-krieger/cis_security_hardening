# @summary 
#    Ensure chrony is configured (Automated)
#
# chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system 
# clocks across a variety of systems and use a source that is highly accurate. More information on chrony 
# can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server.
#
# Rationale:
# If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working 
# properly.
# This recommendation only applies if chrony is in use on the system.
#
# @param enforce
#    Enforce the rule
#
# @param ntp_servers
#    NTP servers to use, depends on the daemon used
#
# @example
#   class ecurity_baseline::rules::common::sec_ntp_daemon_chrony {
#       enforce => true,
#       ntp_servers => ['server1', 'server2'],
#     }
#   }
#
# @api private
class cis_security_hardening::rules::chrony (
  Boolean $enforce   = false,
  Array $ntp_servers = [],
) {
  if $enforce {
    class { 'chrony':
      servers => $ntp_servers,
    }

    if $facts['operatingsystem'].downcase() == 'ubuntu' {
      ensure_packages(['ntp'], {
          ensure => purged,
      })
    }
  }
}

# @summary 
#    Ensure chrony is configured 
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
#    NTP servers to use, add config options per server
#
# @param makestep_seconds
#    Threshold for adjusting system clock.
#
# @param makestep_updates
#    Limit of clock updates since chronyd start.
#
# @example
#   class cis_security_hardening::rules::chrony {
#       enforce => true,
#       ntp_servers => ['server1', 'server2'],
#     }
#   }
#
# @api private
class cis_security_hardening::rules::chrony (
  Boolean $enforce            = false,
  Optional[Hash] $ntp_servers = {},
  Integer $makestep_seconds   = 1,
  Integer $makestep_updates   = 3,
) {
  if $enforce {
    if (empty($ntp_servers)) {
      echo { 'no ntp servers warning':
        message  => 'You have not defined any ntp servers, time updating may not work unless provided by your network DHCP',
        loglevel => 'warning',
        withpath => false,
      }
    }

    class { 'chrony':
      servers          => $ntp_servers,
      makestep_seconds => $makestep_seconds,
      makestep_updates => $makestep_updates,
    }

    case $facts['os']['name'].downcase() {
      'ubuntu': {
        ensure_packages(['ntp'], {
            ensure => purged,
        })
      }
      'rocky', 'almalinux','centos','redhat': {
        file { '/etc/sysconfig/chronyd':
          ensure  => file,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          content => 'OPTIONS="-u chrony"',
        }
      }
      default: {
        # nothing to do
      }
    }
  }
}

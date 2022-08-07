# @summary 
#    Ensure ntp is configured (Automated)
#
# ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system 
# clocks across a variety of systems and use a source that is highly accurate. More information on NTP can 
# be found at http://www.ntp.org. ntp can be configured to be a client and/or a server.
# This recommendation only applies if ntp is in use on the system.
#
# Rationale:
# If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working 
# properly.
#
# @param enforce
#    Enforce the rule
#
# @param ntp_servers
#    NTP servers to use, depends on the daemon used
#
# @param ntp_restrict
#    NTP daemon restrictions depending on the daemon used
#
# @param ntp_driftfile
#    Drift file for ntp daemon
#
# @param ntp_statsdir
#    NTP stats dir
#
# @param ntp_disable_monitor
#    Disables the monitoring facility in NTP
#
# @param ntp_burst
#    Specifies whether to enable the iburst option for every NTP peer.
#
# @param ntp_service_manage
#    Manage ntp service
#
# @example
#   class { 'cis_security_hardening::rules::ntp':
#       enforce => true,
#       ntp_daemon => 'ntp',  
#       ntp_servers => ['server1', 'server2'],
#       }
#   }
#
# @api private
class cis_security_hardening::rules::ntpd (
  Boolean $enforce             = false,
  Array $ntp_servers           = [],
  Array $ntp_restrict          = [],
  String $ntp_driftfile        = '',
  String $ntp_statsdir         = '',
  Boolean $ntp_disable_monitor = true,
  Boolean $ntp_burst           = false,
  Boolean $ntp_service_manage  = true,
) {
  if  $enforce and
  $facts['operatingsystem'].downcase() != 'sles' {
    if(empty($ntp_servers)) {
      fail("Can't configure ntp daemon without ntp servers")
    }
    $ntp_default = {
      servers         => $ntp_servers,
      restrict        => $ntp_restrict,
      disable_monitor => $ntp_disable_monitor,
      iburst_enable   => $ntp_burst,
      service_manage  => $ntp_service_manage,
    }

    if empty($ntp_driftfile) {
      $ntp_drift = {}
    } else {
      $ntp_drift = {
        driftfile       => $ntp_driftfile,
      }
    }

    if empty($ntp_statsdir) {
      $statsdir = {}
    } else {
      $statsdir = {
        statsdir => $ntp_statsdir,
      }
    }

    $ntp_data = $ntp_default + $ntp_drift + $statsdir

    class { 'ntp':
      * => $ntp_data,
    }

    if $facts['osfamily'].downcase() == 'debian' {
      ensure_packages(['chrony'], {
          ensure => purged,
      })
      ensure_resource('service', 'systemd-timesyncd', {
          ensure => stopped,
          enable => false,
      })
      file_line { 'ntp runas':
        ensure => present,
        path   => '/etc/init.d/ntp',
        match  => '^RUNASUSER=',
        line   => 'RUNASUSER=ntp',
      }
    } elsif $facts['osfamily'].downcase() == 'redhat' {
      file { '/etc/sysconfig/ntpd':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => 'OPTIONS="-u ntp:ntp"',
      }
    }
  }
}

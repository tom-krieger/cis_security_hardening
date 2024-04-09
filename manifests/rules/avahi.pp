# @summary
#    Ensure Avahi Server is not enabled
#
# Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery.
# Avahi allows programs to publish and discover services and hosts running on a local network with no specific
# configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers
# to print to, files to look at and people to talk to, as well as network services running on the machine.
#
# Rationale:
# Automatic discovery of network services is not normally required for system functionality. It is recommended
# to disable the service to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::avahi':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::avahi (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged'
    }

    case $facts['os']['name'].downcase {
      'redhat', 'centos': {
        if $facts['os']['release']['major'] >= '8' {
          ensure_resource('service', ['avahi-daemon.socket'], {
              ensure => 'stopped',
              enable => false,
          })
          ensure_resource('service', ['avahi-daemon.service'], {
              ensure => 'stopped',
              enable => false,
          })
        } else {
          ensure_resource('service', ['avahi-daemon'], {
              ensure => 'stopped',
              enable => false,
          })
        }
      }
      'almalinux', 'rocky': {
        ensure_resource('service', ['avahi-daemon.socket'], {
            ensure => 'stopped',
            enable => false,
        })
        ensure_resource('service', ['avahi-daemon.service'], {
            ensure => 'stopped',
            enable => false,
        })
        ensure_packages(['avahi-autoipd', 'avahi'], {
            ensure => $ensure,
        })
      }
      'ubuntu': {
        ensure_resource('service', ['avahi-daemon.socket'], {
            ensure => 'stopped',
            enable => false,
        })
        ensure_resource('service', ['avahi-daemon.service'], {
            ensure => 'stopped',
            enable => false,
        })
        ensure_packages(['avahi-daemon'], {
            ensure => $ensure,
        })
      }
      'debian': {
        if $facts['os']['release']['major'] > '12'{
          exec { 'stop avahi service':
            command => 'systemctl stop avahi-demon.service',
            path    => ['/bin', '/usr/bin'],
            returns => [0, 5],
            unless  => "test \"$(systemctl is-active avahi-daemon.service)\" = \"inactive\"",
            require => Exec['stop avahi socket'],
          }

          exec { 'stop avahi socket':
            command => 'systemctl stop avahi-demon.socket',
            path    => ['/bin', '/usr/bin'],
            returns => [0, 5],
            unless  => "test \"$(systemctl is-active avahi-daemon.socket)\" = \"inactive\"",
          }

          ensure_packages(['avahi-daemon'], {
              ensure => $ensure,
              require => [Exec['stop avahi service'], Exec['stop avahi socket']]
          })
        } else {
          ensure_resource('service', ['avahi-daemon'], {
              ensure => 'stopped',
              enable => false,
          })
        }
      }
      'sles': {
        ensure_resource('service', ['avahi-daemon.socket'], {
            ensure => 'stopped',
            enable => false,
        })
        ensure_resource('service', ['avahi-daemon.service'], {
            ensure => 'stopped',
            enable => false,
        })
        ensure_packages(['avahi-autoipd', 'avahi'], {
            ensure => $ensure,
        })
      }
      default: {
        # Nothing to be done yet
      }
    }
  }
}

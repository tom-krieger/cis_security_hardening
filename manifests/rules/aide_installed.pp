# @summary 
#    Ensure AIDE is installed 
#
# AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes 
# which can then be used to compare against the current state of the filesystem to detect modifications 
# to the system.
#
# Rationale:
# By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure 
# of accidental or malicious misconfigurations or modified binaries.
#
# @param enforce
#    Enforce the rule
#
# @param aide_init_timeout
#    Timeout in secords for aide init command to complete
#
# @example
#   class { 'cis_security_hardening::rules::aide_installed':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::aide_installed (
  Boolean $enforce = false,
  Integer $aide_init_timeout = 1800,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'ubuntu', 'debian': {
        ensure_packages(['aide', 'aide-common'], {
            ensure => installed,
            notify => Exec['aidedb-ubuntu-init'],
        })

        exec { 'aidedb-ubuntu-init':
          command     => 'aideinit',
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          refreshonly => true,
          logoutput   => true,
          notify      => Exec['rename_aidedb_ubuntu'],
          require     => Package['aide', 'aide-common'],
          timeout     => $aide_init_timeout,
        }

        exec { 'rename_aidedb_ubuntu':
          command     => 'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
          creates     => '/var/lib/aide/aide.db',
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          logoutput   => true,
          refreshonly => true,
          require     => Package['aide', 'aide-common'],
        }
      }
      'centos', 'redhat', 'almalinux', 'rocky': {
        ensure_packages(['aide'], {
            ensure => installed,
            notify => Exec['aidedb'],
        })

        exec { 'aidedb':
          command     => 'aide --init',
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          refreshonly => true,
          notify      => Exec['rename_aidedb'],
          require     => Package['aide'],
        }

        exec { 'rename_aidedb':
          command     => 'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
          creates     => '/var/lib/aide/aide.db.gz',
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          logoutput   => true,
          refreshonly => true,
          require     => Package['aide'],
        }
      }
      'sles': {
        ensure_packages(['aide'], {
            ensure => installed,
            notify => Exec['aidedb'],
        })

        exec { 'aidedb':
          command     => 'aide --init',
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          refreshonly => true,
          notify      => Exec['rename_aidedb'],
          require     => Package['aide'],
        }

        exec { 'rename_aidedb':
          command     => 'mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db',
          creates     => '/var/lib/aide/aide.db',
          path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
          logoutput   => true,
          refreshonly => true,
          require     => Package['aide'],
        }
      }
      default: {
      }
    }
  }
}

# @summary 
#    Ensure rsync is not installed or the rsyncd service is masked 
#
# The rsyncd service can be used to synchronize files between systems over network links.
#
# Rationale:
# The rsyncd service presents a security risk as it uses unencrypted protocols for communication.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::rsyncd {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rsyncd (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['os']['family'].downcase() {
      'debian': {
        ensure_packages(['rsync'], {
            ensure => purged,
        })

        ensure_resource('service', ['rsync'], {
            ensure => 'stopped',
            enable => false,
        })

        exec { 'mask rsync daemon':
          command => 'systemctl mask rsync',
          path    => ['/bin', '/usr/bin'],
          onlyif  => 'test "$(systemctl is-enabled rsync)" = "enabled"',
        }
      }
      'suse': {
        ensure_packages(['rsync'], {
            ensure => absent,
        })
      }
      'redhat': {
        if($facts['os']['release']['major'] > '6') {
          $rsyncd_srv = 'rsyncd'
        } else {
          $rsyncd_srv = 'rsync'
        }
        ensure_resource('service', [$rsyncd_srv], {
            ensure => 'stopped',
            enable => false,
        })
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

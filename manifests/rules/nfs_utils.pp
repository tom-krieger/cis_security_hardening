# @summary 
#    Ensure nfs-utils is not installed or the nfs-server service is masked 
#
# The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX 
# environment. It provides the ability for systems to mount file systems of other servers through the network.
#
# Rationale:
# If the system does not require network shares, it is recommended that the nfs-utils package be removed to 
# reduce the attack surface of the system.
# Note: many of the libvirt packages used by Enterprise Linux virtualization are dependent on the nfs-utils package. 
# If the nfs-package is required as a dependency, the nfs-server should be disabled and masked to reduce the 
# attack surface of the system.
#
# @param enforce
#    Enforce the rule
#
# @param uninstall
#    Switch to select if package shoul be uninstalled or service should be masked
#
# @example
#   class { 'cis_security_hardening::rules::nfs_utils':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nfs_utils (
  Boolean $enforce = false,
  Boolean $uninstall = true,
) {
  if $enforce {
    if $uninstall {
      case $facts['os']['name'].downcase() {
        'sles': {
          ensure_packages(['nfs-utils', 'nfs-kernel-server'], {
              ensure => absent,
          })
        }
        'rocky', 'almalinux': {
          ensure_packages(['nfs-utils'], {
              ensure => absent,
          })
        }
        default: {
          ensure_resource('service', 'nfs-server', {
              ensure => stopped,
              enable => false,
          })
          ensure_packages(['nfs-utils'], {
              ensure => absent,
          })
        }
      }
    } else {
      ensure_resource('service', 'nfs-server', {
          ensure => stopped,
          enable => false,
      })
    }
  }
}

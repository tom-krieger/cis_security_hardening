# @summary 
#    Ensure NFS is not enabled (Automated)
#
# The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX 
# environment. It provides the ability for systems to mount file systems of other servers through the network.
#
# Rationale:
# If the system does not export NFS shares, it is recommended that the NFS be disabled to reduce the remote attack 
# surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::nfs':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nfs (
  Boolean $enforce = false,
) {
  if $enforce {
    if $facts['operatingsystem'].downcase() == 'ubuntu' {
      ensure_packages(['nfs-kernel-server'], {
          ensure => purged,
      })
    } else {
      ensure_resource('service', 'nfs', {
          enable => false,
          ensure => stopped,
      })
    }
  }
}

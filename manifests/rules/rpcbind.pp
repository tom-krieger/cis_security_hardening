# @summary 
#    Ensure rpcbind is not installed or the rpcbind services are masked (Automated)
#
# The rpcbind utility maps RPC services to the ports on which they listen. RPC processes notify rpcbind 
# when they start, registering the ports they are listening on and the RPC program numbers they expect to 
# serve. The client system then contacts rpcbind on the server with a particular RPC program number. The 
# rpcbind service redirects the client to the proper port number so it can communicate with the requested 
# service.
#
# Portmapper is an RPC service, which always listens on tcp and udp 111, and is used to map other RPC 
# services (such as nfs, nlockmgr, quotad, mountd, etc.) to their corresponding port number on the server. 
# When a remote host makes an RPC call to that server, it first consults with portmap to determine where 
# the RPC server is listening.
#
# Rationale:
# A small request (~82 bytes via UDP) sent to the Portmapper generates a large response (7x to 28x amplification), 
# which makes it a suitable tool for DDoS attacks. If rpcbind is not required, it is recommended that the rpcbind 
# package be removed to reduce the attack surface of the system.
# 
# Note: many of the libvirt packages used by Enterprise Linux virtualization, and the nfs-utils package used for 
# The Network File System (NFS) are dependent on the rpcbind package. If the rpcbind is required as a dependency, 
# the services rpcbind.service and rpcbind.socket should be stopped and masked to reduce the attack surface of 
# the system.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::rpcbind':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::rpcbind (
  Boolean $enforce = false,
) {
  if $enforce {
    case $facts['operatingsystem'].downcase() {
      'ubuntu': {
        ensure_packages(['rpcbind'], {
            ensure => purged,
        })
      }
      'sles': {
        ensure_resource('service', 'rpcbind', {
            ensure => stopped,
            enable => false,
        })
        ensure_resource('service', 'rpcbind.socket', {
            ensure => stopped,
            enable => false,
        })
        ensure_packages(['rpcbind'], {
            ensure => absent,
        })
      }
      default: {
        ensure_resource('service', ['rpcbind.socket', 'rpcbind'], {
            ensure => 'stopped',
            enable => false,
        })
      }
    }
  }
}

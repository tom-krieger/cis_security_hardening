# @summary 
#    Ensure FTP Server is not installed
#
# FTP (File Transfer Protocol) is a traditional and widely used standard tool for transferring files between a server and clients 
# over a network, especially where no authentication is necessary (permits anonymous users to connect to a server).
# Rationale:
# FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is 
# required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that 
# the package be removed to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class {'cis_security_hardening::rules::ftp':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::ftp (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['os']['family'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }
    ensure_packages(['ftp'], {
        ensure => $ensure,
    })
  }
}

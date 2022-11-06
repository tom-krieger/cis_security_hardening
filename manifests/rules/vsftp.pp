# @summary 
#    Ensure FTP Server is not enabled 
#
# The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.
#
# Rationale:
# FTP does not protect the confidentiality of data or authentication credentials. It is recommended 
# sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server 
# (for example, to allow anonymous downloads), it is recommended that the service be disabled to reduce 
# the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::vsftp':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::vsftp (
  Boolean $enforce = false,
) {
  if $enforce {
    if  $facts['os']['name'].downcase() == 'ubuntu' or $facts['os']['name'].downcase() == 'sles' {
      $ensure = $facts['os']['family'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }

      ensure_packages(['vsftpd'], {
          ensure => $ensure,
      })
    } else {
      ensure_resource('service', ['vsftpd'], {
          ensure => 'stopped',
          enable => false,
      })
    }
  }
}

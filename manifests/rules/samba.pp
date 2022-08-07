# @summary 
#    Ensure Samba is not installed (Automated)
#
# The Samba daemon allows system administrators to configure their Linux systems to share file 
# systems and directories with Windows desktops. Samba will advertise the file systems and 
# directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to 
# mount these directories and file systems as letter drives on their systems.
# 
# Rationale:
# If there is no need to mount directories and file systems to Windows systems, then this service 
# can be disabled to reduce the potential attack surface.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class cis_security_hardening::rules::samba {
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::samba (
  Boolean $enforce = false,
) {
  if $enforce {
    if  $facts['operatingsystem'].downcase() == 'ubuntu' or
    $facts['operatingsystem'].downcase() == 'sles' {
      $ensure = $facts['osfamily'].downcase() ? {
        'suse'  => 'absent',
        default => 'purged',
      }

      ensure_packages(['samba'], {
          ensure => $ensure,
      })
    } else {
      ensure_resource('service', ['smb'], {
          ensure => 'stopped',
          enable => false
      })
    }
  }
}

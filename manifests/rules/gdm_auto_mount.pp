# @summary 
#    Ensure automatic mounting of removable media is disabled
#
# By default GNOME automatically mounts removable media when inserted as a convenience to the user.
#
# Rationale:
# With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents 
# available in system even if they lacked permissions to mount it themselves.
#
# Impact:
# The use of portable hard drives is very common for workstation users. If your organization allows the use of 
# portable storage or media on workstations and physical access controls to workstations is considered adequate 
# there is little value add in turning off automounting.
#
# @param enforce 
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::gdm_auto_mount':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::gdm_auto_mount (
  Boolean $enforce = false,
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    ensure_packages(['dconf'], {
        ensure => present,
    })

    ensure_resource('file', '/etc/dconf/db/local.d', {
        ensure => directory,
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
    })

    if ($facts['os']['name'].downcase() == 'debian') and
    ($facts['os']['release']['major'] > '10') {
      ensure_resource('file', '/etc/dconf/db/local.d/00-media-automount', {
          ensure  => file,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          content => "[org/gnome/desktop/media-handling]\nautorun-never=true\nautorun-never=true\n",
          notify  => Exec['dconf update'],
      })
    } else {
      ensure_resource('file', '/etc/dconf/db/local.d/00-media-automount', {
          ensure  => file,
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          content => "[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false\n",
          notify  => Exec['dconf update'],
      })
    }

    exec { 'dconf update':
      command     => 'dconf update',
      path        => ['/bin', '/usr/bin'],
      refreshonly => true,
    }
  }
}

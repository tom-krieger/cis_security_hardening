# @summary 
#    Ensure GDM login banner is configured 
#
# GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.
#
# Rationale:
# Warning messages inform users who are attempting to login to the system of their legal 
# status regarding the system and must include the name of the organization that owns the 
# system and any monitoring policies that are in place.

# @param enforce
#    Enforce the rule
# @param banner_message
#    The banner message.
#
# @example
#   class { 'cis_security_hardening::rules::gnome_gdm':
#       enforce => true,
#   }
#
# @example
#   include cis_security_hardening::rules::gnome_gdm
#
# @api private
class cis_security_hardening::rules::gnome_gdm (
  Boolean $enforce = false,
  String $banner_message = 'Authorized uses only. All activity may be monitored and reported.',
) {
  $gnome_gdm = fact('cis_security_hardening.gnome_gdm')
  if  $enforce and $gnome_gdm != undef and $gnome_gdm {
    case $facts['os']['name'].downcase() {
      'redhat','centos', 'almalinux', 'rocky': {
        file { 'gdm':
          ensure  => file,
          path    => '/etc/dconf/profile/gdm',
          content => "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults",
        }

        file { '/etc/dconf/db/gdm.d':
          ensure => directory,
          owner  => 'root',
          group  => 'root',
          mode   => '0755',
        }

        file { 'banner-login':
          ensure  => file,
          path    => '/etc/dconf/db/gdm.d/01-banner-message',
          content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'${banner_message}\'", #lint:ignore:140chars
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          require => File['gdm'],
          notify  => Exec['dconf-gdm-exec'],
        }

        file { 'login-screen':
          ensure  => file,
          path    => '/etc/dconf/db/gdm.d/00-login-screen',
          content => "[org/gnome/login-screen]\ndisable-user-list=true",
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          require => File['gdm'],
          notify  => Exec['dconf-gdm-exec'],
        }

        exec { 'dconf-gdm-exec':
          path        => '/bin/',
          command     => 'dconf update',
          refreshonly => true,
        }
      }
      'debian': {
        if $facts['os']['release']['major'] > '10' {
          file { '/etc/dconf/profile/cis':
            ensure  => file,
            content => "user-db:user\nsystem-db:cis\nfile-db:/usr/share/cis/greeter-dconf-defaults",
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
          }

          file { '/etc/dconf/db/cis.d':
            ensure => directory,
            owner  => 'root',
            group  => 'root',
            mode   => '0755',
          }

          file { '/etc/dconf/db/cis.d/01-banner-message':
            ensure  => file,
            content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'\ndisable-user-list=true\n", #lint:ignore:140chars
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
          }
        } else {
          file { '/etc/gdm3/greeter.dconf-defaults':
            ensure  => file,
            content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'\ndisable-user-list=true\n", #lint:ignore:140chars
            owner   => 'root',
            group   => 'root',
            mode    => '0644',
            notify  => Exec['dpkg-gdm-reconfigure'],
          }
        }
        exec { 'dpkg-gdm-reconfigure':
          path        => ['/bin', '/usr/bin'],
          command     => 'dpkg-reconfigure gdm3',
          refreshonly => true,
        }
      }
      'ubuntu': {
        file { '/etc/gdm3/greeter.dconf-defaults':
          ensure  => file,
          content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'\ndisable-user-list=true\n", #lint:ignore:140chars
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          notify  => Exec['dpkg-gdm-reconfigure'],
        }

        exec { 'dpkg-gdm-reconfigure':
          path        => ['/bin', '/usr/bin'],
          command     => 'dpkg-reconfigure gdm3',
          refreshonly => true,
        }
      }
      'sles': {
        file { '/etc/dconf/profile/gdm':
          ensure  => file,
          content => "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n",
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          notify  => Exec['dpkg-gdm-reconfigure'],
        }

        file { '/etc/dconf/db/gdm.d/01-banner-message':
          ensure  => file,
          content => "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text=\'Authorized uses only. All activity may be monitored and reported.\'", #lint:ignore:140chars
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          notify  => Exec['dpkg-gdm-reconfigure'],
        }

        file { '/etc/dconf/db/gdm.d/00- login-screen':
          ensure  => file,
          content => "[org/gnome/login-screen]\ndisable-user-list=true\n",
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          notify  => Exec['dpkg-gdm-reconfigure'],
        }

        exec { 'dpkg-gdm-reconfigure':
          path        => ['/bin', '/usr/bin'],
          command     => 'dconf update',
          refreshonly => true,
        }
      }
      default: {
        # nothing to do yet
      }
    }
  }
}

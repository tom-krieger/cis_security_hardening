# @summary 
#    Change mount options
#
# Change the mount options of a mountpoint.
#
# @param mountpoint
#    Mountpoint to work on
#
# @param mountoptions
#    Options to set
#
# @example
#   cis_security_hardening::set_mount_options { 
#     mountpoint => '/home',
#     mountoptions => 'nodev', 
#   }
define cis_security_hardening::set_mount_options (
  Cis_security_hardening::Mountpoint $mountpoint,
  Cis_security_hardening::Mountoption $mountoptions,
) {
  augeas { "/etc/fstab - work on ${mountpoint} with ${mountoptions}":
    context => '/files/etc/fstab',
    changes => [
      "ins opt after /files/etc/fstab/*[file = '${mountpoint}']/opt[last()]",
      "set *[file = '${mountpoint}']/opt[last()] ${mountoptions}",
    ],
    onlyif  => "match *[file = '${mountpoint}']/opt[. = '${mountoptions}'] size == 0",
    notify  => Exec["remount ${mountpoint} with ${mountoptions}"],
  }

  exec { "remount ${mountpoint} with ${mountoptions}":
    command     => "mount -o remount ${mountpoint}",  #lint:ignore:security_class_or_define_parameter_in_exec
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}

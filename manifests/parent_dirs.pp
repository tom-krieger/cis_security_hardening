# @summary 
#    Create directories recursivly
#
# Create all missing directories
#
# @param dir_path
#    The directories to be created.
#
# @param [Optional[Stdlib::Unixpath]] base_path
#    A base path wich does not need to be created
#
# @param owner
#    The directory owner.
#
# @param group
#    The directoray group.
#
# @param mode
#    The directory permissions.
#
# @example
#   pxe_installarent_dirs{ 'create script dir':
#    dir_path => '/var/www/scripts',
#  }
define cis_security_hardening::parent_dirs (
  Stdlib::Unixpath $dir_path,
  Optional[Stdlib::Unixpath] $base_path = undef,
  Optional[String] $owner               = undef,
  Optional[String] $group               = undef,
  Optional[String] $mode                = undef,
) {
  if $dir_path =~ /\/$/ {
    $_dir_path = "${dir_path}test.conf"
  } else {
    $_dir_path = "${dir_path}/test.conf"
  }

  $_base_path = $base_path ? {
    undef   => '',
    default => if $base_path !~ /\/$/ {
      "${base_path}/"
    } else {
      $base_path
    }
  }

  $dirs = $_dir_path[1,-1].dirname.split('/').reduce([]) |$memo, $subdir| {
    $_dir =  $memo.empty ? {
      true    => if empty($_base_path) {
        "/${subdir}"
      } else {
        "${_base_path}${subdir}"
      },
      default => "${$memo[-1]}/${subdir}",
    }
    concat($memo, $_dir)
  }

  $_owner = $owner ? {
    undef    => {},
    default => {
      owner => $owner,
    }
  }

  $_group = $group ? {
    undef    => {},
    default => {
      group => $group,
    }
  }

  $_mode = $mode ? {
    undef    => {},
    default => {
      mode => $mode,
    }
  }

  $attrs = merge({
      ensure => directory,
  }, $_owner, $_group, $_mode)

  ensure_resource('file', $dirs, $attrs)
}

# @summary 
#    Ensure file systems being imported via NFS are mounted with the "nosuid" option.
#
# The operating system must prevent files with the setuid and setgid bit set from being executed on file systems 
# that are imported via Network File System (NFS).
#
# Rationale:
# The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This 
# option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files 
# from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::nfs_nodev':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nfs_nodev (
  Boolean $enforce = false,
) {
  if $enforce {
    $nfs = fact('cis_security_hardening.nfs_file_systems') ? {
      undef   => {},
      default => fact('cis_security_hardening.nfs_file_systems'),
    }

    $nfs.each |$fs, $data| {
      cis_security_hardening::set_mount_options { "${fs}-nodev":
        mountpoint   => $fs,
        mountoptions => 'nodev',
      }
    }
  }
}

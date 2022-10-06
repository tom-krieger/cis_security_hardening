# @summary 
#    Ensure noexec option is configured for NFS.
#
# The operating system must prevent binary files from being executed on file systems that are being imported via 
# Network File System (NFS).
#
# Rationale:
# The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting 
# any file system not containing approved binary files as they may be incompatible. Executing files from untrusted 
# file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::nfs_noexec':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nfs_noexec (
  Boolean $enforce = false,
) {
  if $enforce {
    $nfs = fact('cis_security_hardening.nfs_file_systems') ? {
      undef   => {},
      default => fact('cis_security_hardening.nfs_file_systems'),
    }

    $nfs.each |$fs, $data| {
      cis_security_hardening::set_mount_options { "${fs}-noexec":
        mountpoint   => $fs,
        mountoptions => 'noexec',
      }
    }
  }
}

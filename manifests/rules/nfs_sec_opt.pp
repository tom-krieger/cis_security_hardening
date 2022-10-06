# @summary
#    Ensure NFS is configured to use RPCSEC_GSS
#
# The operating system must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.
#
# Rationale:
# When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests 
# from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS 
# method of authentication uses certificates on the server and client systems to more securely authenticate the 
# remote mount request.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::nfs_sec_opt':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::nfs_sec_opt (
  Boolean $enforce = false,
) {
  if $enforce {
    $nfs = fact('cis_security_hardening.nfs_file_systems') ? {
      undef   => {},
      default => fact('cis_security_hardening.nfs_file_systems'),
    }

    $nfs.each |$fs, $data| {
      cis_security_hardening::set_mount_options { "${fs}-secopt":
        mountpoint   => $fs,
        mountoptions => 'sec=krb5:krb5i:krb5p',
      }
    }
  }
}

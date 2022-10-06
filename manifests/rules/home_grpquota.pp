# @summary 
#    Ensure grpquota option set on /home partition
#
# The grpquota mount option allows for the filesystem to have disk quotas configured. 
# Rationale:
# To ensure the availability of disk space on /home, it is important to limit the impact a single user or 
# group can cause for other users (or the wider system) by accidentally filling up the partition. Quotas 
# can also be applied to inodes for filesystems where inode exhaustion is a concern.
#
# @param enforce
#    Enforce t5he rule.
#
# @example
#   class { 'cis_security_hardening::rules::home_grpquota':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::home_grpquota (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/home') {
    cis_security_hardening::set_mount_options { '/home-grpquota':
      mountpoint   => '/home',
      mountoptions => 'grpquota',
    }
  }
}

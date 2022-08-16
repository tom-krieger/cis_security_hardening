# @summary 
#    Ensure usrquota option set on /home partition
#
# The usrquota mount option allows for the filesystem to have disk quotas configured. 
#
# Rationale:
# To ensure the availability of disk space on /home, it is important to limit the impact a single user or group can 
# cause for other users (or the wider system) by accidentally filling up the partition. Quotas can also be applied 
# to inodes for filesystems where inode exhaustion is a concern.
#
# @param enforce
#    Enforce the rule.
#
# @example
#   class { 'cis_security_hardening::rules::home_usrquota':
#     enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::home_usrquota (
  Boolean $enforce = false,
) {
  if ($enforce) and has_key($facts['mountpoints'], '/home') {
    cis_security_hardening::set_mount_options { '/home-usrquota':
      mountpoint   => '/home',
      mountoptions => 'quota,usrquota',
    }
  }
}

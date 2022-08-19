# @summary 
#    Ensure default group for the root account is GID 0 
#
# The usermod command can be used to specify which group the root user belongs to. This affects 
# permissions of files that are created by the root user.
#
# Rationale:
# Using GID 0 for the root account helps prevent root -owned files from accidentally becoming 
# accessible to non-privileged users.
#
# @param enforce
#    Enforce the rule
#
# @param encrypted_root_password
#    The nre root password o be set (has to be encrypted as the OS needs it)
#
# @example
#   class { 'cis_security_hardening::rules::root_gid':
#       enforce => true,
#       encrypted_root_password => 'encrypted password',
#   }
#
# @api private
class cis_security_hardening::rules::root_gid (
  Boolean $enforce                = false,
  String $encrypted_root_password = '',
) {
  if($enforce) {
    if empty($encrypted_root_password) {
      $data = {
        ensure => present,
        gid    => '0',
      }
    } else {
      $data = {
        ensure   => present,
        gid      => '0',
        password => $encrypted_root_password,
      }
    }
    ensure_resource('user', 'root', $data)
  }
}

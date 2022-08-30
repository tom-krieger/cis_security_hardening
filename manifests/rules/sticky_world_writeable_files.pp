# @summary 
#    Ensure sticky bit is set on all world-writable directories 
#
# Setting the sticky bit on world writable directories prevents users from deleting or renaming files in 
# that directory that are not owned by them.
#
# Rationale:
# This feature prevents the ability to delete or rename files in world writable directories (such as /tmp ) 
# that are owned by another user.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::sticky_world_writeable_files':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::sticky_world_writeable_files (
  Boolean $enforce = false,
) {
  $world_writable = fact('cis_security_hardening.world_writable')

  if  $enforce and $world_writable != undef {
    $world_writable.each | $file | {
      ensure_resource('file', $file, {
          mode => 'a+t',
      })
    }
  }
}

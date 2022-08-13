# @summary 
#    Ensure system command files are group-owned by root
#
# The operating system must have system commands group-owned by root.
#
# Rationale:
# If the Ubuntu operating system were to allow any user to make changes to software libraries, then 
# those changes might be implemented without undergoing the appropriate testing and approvals that 
# are part of a robust change management process.
#
# This requirement applies to Ubuntu operating systems with software libraries that are accessible and 
# configurable, as in the case of interpreted languages. Software libraries also include privileged 
# programs which execute with escalated privileges. Only qualified and authorized individuals must be 
# allowed to obtain access to information system components for purposes of initiating changes, including 
# upgrades and modifications.
#
# @param enforce
#    Enforce the rule.
# @param syswtem_dirs
#    List of directories to configure.
#
# @example
#   class { 'cis_security_hardening::rules::system_cmd_group':
#     enforce => true,
#     system_dirs => ['/bin','/sbin'],
#   }
# 
# @api private
class cis_security_hardening::rules::system_cmd_group (
  Boolean $enforce   = false,
  Array $system_dirs = ['/bin','/sbin','/usr/bin','/usr/sbin','/usr/local/bin','/usr/local/sbin'],
) {
  if $enforce {

    $system_dirs.each |$system_dir| {

      file { $system_dir:
        group => 'root',
      }

    }
  }
}

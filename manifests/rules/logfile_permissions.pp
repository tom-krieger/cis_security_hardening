# @summary 
#    Ensure permissions on all logfiles are configured 
#
# Log files stored in /var/log/ contain logged information from many services on the system, 
# or on log hosts others as well.
#
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure that sensitive 
# data is archived and protected.
#
# @param enforce
#    Enforce the rule
# @param file_mode
#    Mode to set files to
# @param [Optional[String]] dir_mode
#    Directory mode to set
# @param exclude_files
#    Files not to change the permissions
#
# @example
#   class { 'cis_security_hardening::rules::logfile_permissions':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::logfile_permissions (
  Boolean $enforce = false,
  String $file_mode = '0640',
  Optional[String] $dir_mode = undef,
  Optional[Array] $exclude_files = undef,
) {
  if $enforce {
    $data = $dir_mode ? {
      undef   => {
        file_mode => $file_mode,
      },
      default => {
        file_mode => $file_mode,
        dir_mode => $dir_mode,
      },
    }
    recursive_file_permissions { '/var/log':
      * => $data,
    }
  }
}

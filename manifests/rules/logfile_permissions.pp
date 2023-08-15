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
#
# @example
#   class { 'cis_security_hardening::rules::logfile_permissions':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::logfile_permissions (
  Boolean $enforce = false,
) {
  if $enforce {
    # ensure_resource('file', '/var/log', {
    #     ensure  => directory,
    #     recurse => true,
    #     mode    => 'g-wx,o-rwx',     #lint:ignore:no_symbolic_file_modes
    #     ignore  => ['puppetlabs', 'puppet'],
    # })

    recursive_file_permissions { '/var/log':
      file_mode => '0640',
    }
  }
}

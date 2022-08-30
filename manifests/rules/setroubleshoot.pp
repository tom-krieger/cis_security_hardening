# @summary 
#    Ensure SETroubleshoot is not installed 
#
# The SETroubleshoot service notifies desktop users of SELinux denials through a user- friendly interface. 
# The service provides important information around configuration errors, unauthorized intrusions, and other 
# potential errors.
#
# Rationale:
# The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled.
#
# @param enforce
#    Enforce the rule
#
# @example
#   class { 'cis_security_hardening::rules::setroubleshoot':
#       enforce => true,
#   }
#
# @api public
class cis_security_hardening::rules::setroubleshoot (
  Boolean $enforce = false,
) {
  if $enforce {
    $ensure = $facts['osfamily'].downcase() ? {
      'suse'  => 'absent',
      default => 'purged',
    }
    ensure_packages(['setroubleshoot'], {
        ensure => $ensure,
    })
  }
}

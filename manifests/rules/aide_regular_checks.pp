# @summary
#    Ensure filesystem integrity is regularly checked 
#
# Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.
#
# Rationale:
# Periodic file checking allows the system administrator to determine on a regular basis if critical 
# files have been changed in an unauthorized fashion.
#
# @param enforce
#    Enforce the rule
#
# @param hour
#    Cron hour.
#
# @param minute
#     Cron minute.
#
# @example
#   class { 'cis_security_hardening::rules::aide_regular_checks':
#       enforce => true,
#   }
#
# @api private
class cis_security_hardening::rules::aide_regular_checks (
  Boolean $enforce = false,
  Integer $hour    = 0,
  Integer $minute  = 5,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'centos', 'redhat', 'sles', 'almalinux', 'rocky': {
        $content = "${hour} ${minute} * * * root /usr/sbin/aide --check\n"
      }
      'ubuntu', 'debian': {
        $content = "${hour} ${minute} * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check\n"
      }
      default: {
        $content = ''
      }
    }

    if ! empty($content) {
      file { '/etc/cron.d/aide.cron':
        ensure  => absent,
      }
      file { '/etc/cron.d/aide':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => $content,
      }
    }
  }
}

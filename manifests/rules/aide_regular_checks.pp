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
# @param use_systemd
#    Use systemd for perioding aide work instead of cronjbs.
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
  Boolean $use_systemd = false,
  Integer $hour    = 0,
  Integer $minute  = 5,
) {
  if $enforce {
    case $facts['os']['name'].downcase() {
      'centos', 'redhat', 'sles', 'almalinux', 'rocky': {
        $aide_bin = '/usr/sbin/aide'
        $config = ''
        $content = "${hour} ${minute} * * * root ${aide_bin} --check\n"
      }
      'ubuntu', 'debian': {
        $aide_bin = '/usr/bin/aide.wrapper'
        $config = '/etc/aide/aide.conf'
        $content = "${hour} ${minute} * * * ${aide_bin} --config ${config} --check\n"
      }
      default: {
        $content = ''
        $aide_bin = ''
        $config = ''
      }
    }

    if $use_systemd {
      if ! empty($aide_bin) {
        file { '/etc/systemd/system/aidecheck.service':
          ensure  => file,
          content => epp('cis_security_hardening/rules/common/aidecheck.service.epp', {
              aide_bin => $aide_bin,
              config   => $config,
          }),
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          notify  => Exec['systemd-daemon-reload'],
        }
        file { '/etc/systemd/system/aidecheck.timer':
          ensure  => file,
          content => epp('cis_security_hardening/rules/common/aidecheck.timer.epp', {}),
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          notify  => [Exec['systemd-daemon-reload'], Exec['enable-aidecheck-timer']],
        }

        service { 'aidecheck.service':
          enable  => true,
          require => File['/etc/systemd/system/aidecheck.service'],
        }

        exec { 'enable-aidecheck-timer':
          command     => 'systemctl --now enable aidecheck.timer',
          path        => ['/bin', '/usr/bin'],
          refreshonly => true,
        }
      }
    } else {
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
}

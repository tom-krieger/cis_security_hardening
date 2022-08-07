# @summary 
#    Services
#
# Several exec resources needed from multiple classes.
#
# @param time_until_reboot
#    Time to wait until system is rebooted if required. Time in seconds.
#
# @example
#   include cis_security_hardening::services
class cis_security_hardening::services (
  Integer $time_until_reboot = 60,
) {
  if(has_key($facts, 'os')) {
    $rel = $facts['operatingsystemmajrelease']
  } else {
    $rel = ''
  }
  if (
    ($rel <= '6') and
    ($facts['osfamily'] == 'RedHat')
  ) {
    exec { 'reload-sshd':
      command     => 'service sshd reload',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  } else {
    exec { 'reload-sshd':
      command     => 'systemctl reload sshd',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  }

  exec { 'reload-rsyslog':
    command     => 'pkill -HUP rsyslog',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'reload-rsyslogd':
    command     => 'pkill -HUP rsyslogd',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'reload-syslog-ng':
    command     => 'pkill -HUP syslog-ng',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'authselect-apply-changes':
    command     => 'authselect apply-changes',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'systemd-daemon-reload':
    command     => 'systemctl daemon-reload',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  reboot { 'after_run':
    timeout => $time_until_reboot,
    message => 'forced reboot by Puppet',
    apply   => 'finished',
  }
}

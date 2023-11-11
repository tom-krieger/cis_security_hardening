# @summary
#    Services
#
# Several exec resources needed from multiple classes.
#
# @example
#   include cis_security_hardening::services
class cis_security_hardening::services {
  $sshd_reload_command = if fact('os.release.major') <= '6' and fact('os.family') == 'redhat' {
    'service sshd reload'
  } else {
    'systemctl reload sshd'
  }

  exec { 'reload-sshd':
    command     => $sshd_reload_command,
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
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

  exec { 'save iptables rules':
    command     => 'service iptables save',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    unless      => 'test -z "$(grep -e AlmaLinux -e Rocky /etc/redhat-release 2>/dev/null)"',
    refreshonly => true,
  }

  exec { 'authconfig-apply-changes':
    command     => 'authconfig --updateall',
    path        => ['/sbin','/usr/sbin'],
    refreshonly => true,
  }

  exec { 'grub2-mkconfig':
    command     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }

  exec { 'reload-sysctl-system':
    command     => 'sysctl --system',
    path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
    refreshonly => true,
  }
}

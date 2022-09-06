# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::services' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it {
        is_expected.to compile

        if os_facts[:operatingsystemmajrelease] == '6' && os_facts[:osfamily] == 'RedHat'
          is_expected.to contain_exec('reload-sshd')
            .with(
              'command'     => 'service sshd reload',
              'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'refreshonly' => true,
            )
        else
          is_expected.to contain_exec('reload-sshd')
            .with(
              'command'     => 'systemctl reload sshd',
              'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'refreshonly' => true,
            )
        end

        is_expected.to contain_exec('reload-rsyslogd')
          .with(
            'command'     => 'pkill -HUP rsyslogd',
            'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            'refreshonly' => true,
          )

        is_expected.to contain_exec('reload-rsyslog')
          .with(
            'command'     => 'pkill -HUP rsyslog',
            'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            'refreshonly' => true,
          )

        is_expected.to contain_exec('reload-syslog-ng')
          .with(
            'command'     => 'pkill -HUP syslog-ng',
            'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            'refreshonly' => true,
          )

        is_expected.to contain_exec('authselect-apply-changes')
          .with(
            'command'     => 'authselect apply-changes',
            'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            'refreshonly' => true,
          )

        is_expected.to contain_exec('systemd-daemon-reload')
          .with(
            'command'     => 'systemctl daemon-reload',
            'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            'refreshonly' => true,
          )

        is_expected.to contain_exec('save iptables rules')
          .with(
              'command'    => 'service iptables save',
              'path'       => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'unless'     => 'test -z "$(grep -e AlmaLinux -e Rocky /etc/redhat-release 2>/dev/null)"',
              'refreshonly' => true,
            )

        is_expected.to contain_exec('authconfig-apply-changes')
          .with(
              'command'    => 'authconfig --updateall',
              'path'       => ['/sbin', '/usr/sbin'],
              'refreshonly' => true,
            )

        is_expected.to contain_exec('grub2-mkconfig')
          .with(
            'command'     => 'grub2-mkconfig -o /boot/grub2/grub.cfg',
            'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            'refreshonly' => true,
          )

        is_expected.to contain_exec('reload-sysctl-system')
          .with(
          'command'     => 'sysctl --system',
          'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          'refreshonly' => true,
        )

        is_expected.to contain_reboot('after_run')
          .with(
            'timeout' => 60,
            'message' => 'forced reboot by Puppet',
            'apply'   => 'finished',
          )
      }
    end
  end
end

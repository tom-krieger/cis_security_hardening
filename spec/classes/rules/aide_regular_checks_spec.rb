# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
systemd_options = [true, false]

describe 'cis_security_hardening::rules::aide_regular_checks' do
  let(:pre_condition) do
    <<-EOF
    exec { 'systemd-daemon-reload':
      command     => 'systemctl daemon-reload',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      systemd_options.each do |systemd|
        context "on #{os} with enforce = #{enforce} and systemd = #{systemd}" do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'use_systemd' => systemd,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if systemd
                is_expected.not_to contain_file('/etc/cron.d/aide')
                is_expected.not_to contain_file('/etc/cron.d/aide.cron')
                is_expected.to contain_file('/etc/systemd/system/aidecheck.service')
                  .with(
                    'ensure'  => 'file',
                    'owner'   => 'root',
                    'group'   => 'root',
                    'mode'    => '0644',
                  )
                  .that_notifies('Exec[systemd-daemon-reload]')
                is_expected.to contain_file('/etc/systemd/system/aidecheck.timer')
                  .with(
                    'ensure'  => 'file',
                    'owner'   => 'root',
                    'group'   => 'root',
                    'mode'    => '0644',
                  )
                  .that_notifies(['Exec[systemd-daemon-reload]', 'Exec[enable-aidecheck-timer]'])
                is_expected.to contain_service('aidecheck.service')
                  .with(
                    'enable'  => true,
                  )
                  .that_requires('File[/etc/systemd/system/aidecheck.service]')
                is_expected.to contain_exec('enable-aidecheck-timer')
                  .with(
                    'command'     => 'systemctl --now enable aidecheck.timer',
                    'path'        => ['/bin', '/usr/bin'],
                    'refreshonly' => true,
                  )
              else
                is_expected.not_to contain_file('/etc/systemd/system/aidecheck.service')
                is_expected.not_to contain_file('/etc/systemd/system/aidecheck.timer')
                is_expected.not_to contain_service('aidecheck.service')
                is_expected.not_to contain_exec('enable-aidecheck-timer')
                is_expected.to contain_file('/etc/cron.d/aide')
                  .with(
                    'ensure' => 'file',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )

                is_expected.to contain_file('/etc/cron.d/aide.cron')
                  .with(
                    'ensure' => 'absent',
                  )
              end
            end
          }
        end
      end
    end
  end
end

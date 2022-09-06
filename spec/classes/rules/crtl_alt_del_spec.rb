# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::crtl_alt_del' do
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
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('mask ctrl-alt-del.target')
              .with(
                'command' => 'systemctl mask ctrl-alt-del.target',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(systemctl status ctrl-alt-del.target | grep -i "Loaded: masked")"',
              )
              .that_notifies('Exec[systemd-daemon-reload]')

            if os_facts[:operatingsystem].casecmp('redhat').zero? && (os_facts[:operatingsystemmajrelease] >= '8')
              is_expected.to contain_file_line('ctrl-alt-del-burst')
                .with(
                  'ensure'             => 'present',
                  'path'               => '/etc/systemd/system.conf',
                  'match'              => '^CtrlAltDelBurstAction=',
                  'line'               => 'CtrlAltDelBurstAction=none',
                  'append_on_no_match' => true,
                )
                .that_notifies('Exec[systemd-daemon-reload]')
            end
          else
            is_expected.not_to contain_exec('mask ctrl-alt-del.target')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_coredump_socket' do
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
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('mask coredump.socket')
              .with(
                'command' => 'systemctl mask systemd-coredump.socket',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(systemctl status systemd-coredump.socket | grep -i "Loaded: masked")"',
              )
              .that_notifies('Exec[systemd-daemon-reload]')
          else
            is_expected.not_to contain_exec('mask coredump.socket')
          end
        }
      end
    end
  end
end

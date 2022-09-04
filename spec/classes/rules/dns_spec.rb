# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dns' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'nsswitch_entry' => 'files dns',
            'dns_servers' => ['8.8.8.8', '8.8.4.4'],
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('nsswitch dns')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/nsswitch.conf',
                'match'  => '^hosts:',
                'line'   => 'hosts: files dns',
              )

            is_expected.to contain_file('/etc/resolv.conf')
              .with(
                'ensure'  => 'file',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
              )
              .that_notifies('Exec[resolv.conf immutable]')

            is_expected.to contain_exec('resolv.conf immutable')
              .with(
                'command'     => 'chattr +i /etc/resolv.conf',
                'path'        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                'refreshonly' => true,
              )
          else
            is_expected.not_to contain_file_line('nsswitch dns')
            is_expected.not_to contain_file('/etc/resolv.conf')
            is_expected.not_to contain_exec('resolv.conf immutable')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::chrony' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'ntp_servers' => {
              '10.10.10.1' => ['iburst', 'maxpoll 17'],
              '10.10.10.2' => ['iburst', 'maxpoll 17'],
            },
            'makestep_seconds' => 1,
            'makestep_updates' => -1,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_class('chrony')
              .with(
                'servers' => {
                  '10.10.10.1' => ['iburst', 'maxpoll 17'],
                  '10.10.10.2' => ['iburst', 'maxpoll 17'],
                },
                'makestep_seconds' => 1,
                'makestep_updates' => -1,
              )

            if os_facts[:operatingsystem].casecmp('ubuntu').zero?
              is_expected.to contain_package('ntp')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
              is_expected.to contain_file('/etc/sysconfig/chronyd')
                .with(
                  'ensure'  => 'file',
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                  'content' => 'OPTIONS="-u chrony"',
                )

            end
          else
            is_expected.not_to contain_class('chrony')
            is_expected.not_to contain_package('ntp')
            is_expected.not_to contain_file('/etc/sysconfig/chronyd')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::avahi' do
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

            if os_facts[:os]['name'].casecmp('redhat').zero? || os_facts[:os]['name'].casecmp('centos').zero?

              if os_facts[:os]['release']['major'] < '8'
                is_expected.to contain_service('avahi-daemon')
                  .with(
                    'ensure' => 'stopped',
                    'enable' => false,
                  )
              else
                is_expected.to contain_service('avahi-daemon.socket')
                  .with(
                    'ensure' => 'stopped',
                    'enable' => false,
                  )
                is_expected.to contain_service('avahi-daemon.service')
                  .with(
                    'ensure' => 'stopped',
                    'enable' => false,
                  )
              end

            elsif os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?
              is_expected.to contain_service('avahi-daemon.socket')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('avahi-daemon.service')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_package('avahi-autoipd')
                .with(
                  'ensure' => 'purged',
                )

              is_expected.to contain_package('avahi')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:os]['name'].casecmp('ubuntu').zero?

              is_expected.to contain_service('avahi-daemon.socket')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('avahi-daemon.service')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )

              is_expected.to contain_package('avahi-daemon')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:os]['name'].casecmp('sles').zero?

              is_expected.to contain_service('avahi-daemon.socket')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('avahi-daemon.service')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )

              is_expected.to contain_package('avahi-autoipd')
                .with(
                  'ensure' => 'absent',
                )

              is_expected.to contain_package('avahi')
                .with(
                  'ensure' => 'absent',
                )
            end

          else
            is_expected.not_to contain_service('avahi-daemon')
            is_expected.not_to contain_service('avahi-daemon.socket')
            is_expected.not_to contain_service('avahi-daemon.service')
            is_expected.not_to contain_package('avahi-daemon')
          end
        }
      end
    end
  end
end

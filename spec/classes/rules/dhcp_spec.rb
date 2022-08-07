# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dhcp' do
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

            if os_facts[:operatingsystem].casecmp('ubuntu').zero?
              is_expected.to contain_package('isc-dhcp-server')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:operatingsystem].casecmp('debian').zero?
              is_expected.to contain_service('isc-dhcp-server')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('isc-dhcp-server6')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            elsif os_facts[:operatingsystem].casecmp('sles').zero?
              is_expected.to contain_package('dhcp')
                .with(
                  'ensure' => 'absent',
                )
            else
              is_expected.to contain_service('dhcpd')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            end
          else
            is_expected.not_to contain_service('dhcpd')
            is_expected.not_to contain_package('isc-dhcp-server')
            is_expected.not_to contain_package('isc-dhcp-server6')
            is_expected.not_to contain_package('dhcp')
          end
        }
      end
    end
  end
end

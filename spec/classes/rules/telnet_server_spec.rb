# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::telnet_server' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            unless os_facts[:os]['name'].casecmp('sles').zero?
              is_expected.to contain_service('telnet')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            end

            if os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_package('telnet-server')
                .with(
                  'ensure' => 'absent',
                )
            elsif os_facts[:os]['family'].casecmp('ubuntu').zero? || os_facts[:os]['family'].casecmp('debian').zero?
              is_expected.to contain_package('telnetd')
                .with(
                  'ensure' => 'purged',
                )
            else
              is_expected.to contain_package('telnet-server')
                .with(
                  'ensure' => 'purged',
                )
            end
          else
            is_expected.not_to contain_service('telnet')
            is_expected.not_to contain_package('telnet-server')
            is_expected.not_to contain_package('telnetd')
          end
        }
      end
    end
  end
end

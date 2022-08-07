# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rpcbind' do
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
              is_expected.to contain_package('rpcbind')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:operatingsystem].casecmp('sles').zero?
              is_expected.to contain_package('rpcbind')
                .with(
                  'ensure' => 'absent',
                )
              is_expected.to contain_service('rpcbind')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('rpcbind.socket')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            else
              is_expected.to contain_service('rpcbind.socket')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('rpcbind')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            end
          else
            is_expected.not_to contain_service('rpcbind.socket')
            is_expected.not_to contain_service('rpcbind')
            is_expected.not_to contain_package('rpcbind')
          end
        }
      end
    end
  end
end

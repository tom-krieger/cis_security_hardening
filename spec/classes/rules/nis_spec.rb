# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nis' do
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

            if os_facts[:os]['name'].casecmp('ubuntu').zero?
              is_expected.to contain_package('nis')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:os]['name'].casecmp('sles').zero?
              is_expected.to contain_package('ypserv')
                .with(
                  'ensure' => 'absent',
                )
            else
              is_expected.to contain_service('ypserv')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            end
          else
            is_expected.not_to contain_service('ypserv')
            is_expected.not_to contain_package('ypserv')
            is_expected.not_to contain_package('nis')
          end
        }
      end
    end
  end
end

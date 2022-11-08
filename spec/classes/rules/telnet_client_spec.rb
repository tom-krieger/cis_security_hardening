# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::telnet_client' do
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
            if os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_package('telnet')
                .with(
                'ensure' => 'absent',
              )
            else
              is_expected.to contain_package('telnet')
                .with(
                'ensure' => 'purged',
              )
            end

          else
            is_expected.not_to contain_package('telnet')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gnome_gdm_package' do
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
            if os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_package('gdm')
                .with(
                  'ensure' => 'absent',
                )
              is_expected.not_to contain_package('gdm3')
            else
              is_expected.to contain_package('gdm3')
                .with(
                  'ensure' => 'purged',
                )
              is_expected.not_to contain_package('gdm')
            end
          else
            is_expected.not_to contain_package('gdm3')
            is_expected.not_to contain_package('gdm')
          end
        }
      end
    end
  end
end

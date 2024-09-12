# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_libpwquality' do
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
          is_expected.to compile.with_all_deps

          if enforce
            # if os_facts[:os]['name'].casecmp('centos').zero?
            is_expected.to contain_package('libpwquality')
              .with(
                'ensure' => 'installed',
              )
            # else
            #   is_expected.not_to contain_package('libpwquality')
            # end
          else
            is_expected.not_to contain_package('libpwquality')
          end
        }
      end
    end
  end
end

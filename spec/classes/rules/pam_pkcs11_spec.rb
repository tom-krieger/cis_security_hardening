# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_pkcs11' do
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
            if os_facts[:osfamily].casecmp('redhat').zero?
              is_expected.to contain_package('esc')
                .with(
                  'ensure' => 'present',
                
                )
              is_expected.to contain_package('pam-pkcs11')
                .with(
                  'ensure' => 'present',
                )
            else
              is_expected.to contain_package('libpam-pkcs11')
              .with(
                'ensure' => 'present',
              )
            end
          else
            is_expected.not_to contain_package('libpam-pkcs11')
            is_expected.not_to contain_package('esc')
            is_expected.not_to contain_package('pam-pkcs11')
          end
        }
      end
    end
  end
end

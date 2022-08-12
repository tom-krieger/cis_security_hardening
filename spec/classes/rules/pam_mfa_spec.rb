# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_mfa' do
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
            is_expected.to contain_pam('pam-common-mfa')
              .with(
                'ensure'           => 'present',
                'service'          => 'common-auth',
                'type'             => 'auth',
                'control'          => '[success=2 default=ignore]',
                'control_is_param' => true,
                'module'           => 'pam_pkcs11.so',
              )
          else
            is_expected.not_to contain_pam('pam-common-mfa')
          end
        }
      end
    end
  end
end

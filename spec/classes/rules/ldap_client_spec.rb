# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ldap_client' do
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

            if os_facts[:operatingsystem].casecmp('ubuntu').zero? || os_facts[:operatingsystem].casecmp('debian').zero?
              is_expected.to contain_package('ldap-utils')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:operatingsystem].casecmp('sles').zero?
              is_expected.to contain_package('openldap2-clients')
                .with(
                  'ensure' => 'absent',
                )
            else
              is_expected.to contain_package('openldap-clients')
                .with(
                  'ensure' => 'purged',
                )
            end
          else
            is_expected.not_to contain_package('openldap-clients')
            is_expected.not_to contain_package('openldap2-clients')
            is_expected.not_to contain_package('ldap-utils')
          end
        }
      end
    end
  end
end

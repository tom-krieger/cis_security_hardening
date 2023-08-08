# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::httpd' do
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

            if os_facts[:os]['name'].casecmp('ubuntu').zero? || os_facts[:os]['name'].casecmp('debian').zero?
              is_expected.to contain_package('apache2')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:os]['name'].casecmp('sles').zero?
              is_expected.to contain_package('httpd')
                .with(
                  'ensure' => 'absent',
                )
            elsif os_facts[:os]['name'].casecmp('redhat').zero?
              is_expected.to contain_package('httpd')
                .with(
                  'ensure' => 'purged',
                )
              if os_facts[:os]['release']['major'] >= '9'
                is_expected.to contain_package('nginx')
                  .with(
                    'ensure' => 'purged',
                  )
              end
            else
              is_expected.to contain_service('httpd')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            end
          else
            is_expected.not_to contain_service('httpd')
            is_expected.not_to contain_package('httpd')
            is_expected.not_to contain_package('apache2')
          end
        }
      end
    end
  end
end

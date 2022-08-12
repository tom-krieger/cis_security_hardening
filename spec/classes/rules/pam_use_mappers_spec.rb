# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_use_mappers' do
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
            is_expected.to contain_file('/etc/pam_pkcs11/pam_pkcs11.conf')
                .with(
                  'ensure' => 'file',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0644',
                )
            
            is_expected.to contain_file_line('pam use mappers')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/pam_pkcs11/pam_pkcs11.conf',
                'line'   => 'use_mappers = pwent',
                'match'  => '^#?use_mappers',
              )
              .that_requires('File[/etc/pam_pkcs11/pam_pkcs11.conf]')
          end
        }
      end
    end
  end
end

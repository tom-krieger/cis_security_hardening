# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::opassword_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/security/opasswd')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )

            is_expected.to contain_file('/etc/security/opasswd.old')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )
          else
            is_expected.not_to contain_file('/etc/security/opasswd')
            is_expected.not_to contain_file('/etc/security/opasswd.old')
          end
        }
      end
    end
  end
end

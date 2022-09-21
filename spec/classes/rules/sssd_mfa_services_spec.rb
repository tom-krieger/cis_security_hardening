# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sssd_mfa_services' do
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
            is_expected.to contain_file('/etc/sssd/sssd.conf')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0644',
              )
            is_expected.to contain_file_line('sssd mfa')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/sssd/sssd.conf',
                'match'  => '^services =',
                'line'   => 'services = nss, pam',
              )
          else
            is_expected.not_to contain_file('/etc/sssd/sssd.conf')
          end
        }
      end
    end
  end
end

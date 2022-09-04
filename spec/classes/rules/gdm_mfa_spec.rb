# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_mfa' do
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
            is_expected.to contain_file('/etc/dconf/db/local.d/00-defaults')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_file_line('mfa')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/dconf/db/local.d/00-defaults',
                'match'              => '^enable-smartcard-authentication',
                'line'               => 'enable-smartcard-authentication=true',
                'append_on_no_match' => true,
              )
              .that_requires('File[/etc/dconf/db/local.d/00-defaults]')
          else
            is_expected.not_to contain_file('/etc/dconf/db/local.d/00-defaults')
            is_expected.not_to contain_file_line('mfa')
          end
        }
      end
    end
  end
end

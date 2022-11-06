# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::passwd_sha512' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'pw_data' => {
                'pass_max_days_status' => true,
                'inactive_status' => true,
                'inactive' => 25,
                'pw_change_in_future' => true,
                'pass_min_days_status' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile
          if enforce
            path = if os_facts[:os]['name'] == 'SLES' && os_facts[:os]['release']['major'] == '12'
                     '/usr/etc/login.defs'
                   else
                     '/etc/login.defs'
                   end
            is_expected.to contain_file_line('password sha512')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'ENCRYPT_METHOD SHA512',
                'match'  => '^#?ENCRYPT_METHOD',
              )
          else
            is_expected.not_to contain_file_line('password sha512')
          end
        }
      end
    end
  end
end

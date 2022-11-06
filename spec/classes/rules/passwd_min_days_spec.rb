# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::passwd_min_days' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'local_users' => {
                'test1' => {
                  'account_expires_days' => 25,
                  'last_password_change_days' => 8,
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 14,
                  'password_date_valid' => false,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 35,
                  'warn_days_between_password_change' => 7,
                },
              },
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
            'min_pass_days' => 7,
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
            is_expected.to contain_file_line('password min days password change')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'PASS_MIN_DAYS 7',
                'match'  => '^#?PASS_MIN_DAYS',
              )

            is_expected.to contain_exec('chage --mindays 7 test1')
              .with(
                'path' => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )
          else
            is_expected.not_to contain_exec('chage --mindays 7 test1')
            is_expected.not_to contain_file_line('password min days password change')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::passwd_expiration' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'local_users' => {
                'test1' => {
                  'account_expires_days' => 25,
                  'last_password_change_days' => 8,
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 7,
                  'password_date_valid' => true,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 30,
                  'warn_days_between_password_change' => 7,
                },
                'root' => {
                  'account_expires_days' => 25,
                  'last_password_change_days' => 8,
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 7,
                  'password_date_valid' => true,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 30,
                  'warn_days_between_password_change' => 7,
                },
              },
              'pw_data' => {
                'pass_max_days_status' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'max_pass_days' => 90,
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
            is_expected.to contain_file_line('password expiration policy')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'PASS_MAX_DAYS 90',
                'match'  => '^#?PASS_MAX_DAYS',
              )
            is_expected.to contain_exec('chage --maxdays 90 test1')
              .with(
                'path' => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )

            is_expected.to contain_exec('chage --maxdays 90 root')
              .with(
                'path' => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )
          else
            is_expected.not_to contain_file_line('password expiration policy')
            is_expected.not_to contain_exec('chage --maxdays 90 test1')
            is_expected.not_to contain_exec('chage --maxdays 90 root')
          end
        }
      end
    end
  end
end

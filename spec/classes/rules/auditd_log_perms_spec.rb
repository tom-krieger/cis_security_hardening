# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_log_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              auditd: {
                uid_min: '1000',
                auditing_process: 'none',
                log_files: ['/var/log/audit/audit.log', '/var/log/audit/audit.log.1']
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'user' => 'root',
            'group' => 'root',
            'mode' => '0600',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/var/log/audit/audit.log')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0600',
              )
            is_expected.to contain_file('/var/log/audit/audit.log.1')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0600',
              )
          else
            is_expected.not_to contain_file('/var/log/audit/audit.log')
            is_expected.not_to contain_file('/var/log/audit/audit.log.1')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_max_log_file_action' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              auditd: {
                uid_min: '1000',
                'max_log_file' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'max_log_file_action' => 'keep_logs',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('auditd_max_log_file_action')
              .with(
                'path'  => '/etc/audit/auditd.conf',
                'line'  => 'max_log_file_action = keep_logs',
                'match' => '^max_log_file_action',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('auditd_max_log_file_action')
          end
        }
      end
    end
  end
end

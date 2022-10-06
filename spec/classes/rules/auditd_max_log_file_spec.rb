# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_max_log_file' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              auditd: {
                'max_log_file' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'max_log_size' => 16,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('auditd_max_log_size')
              .with(
                'path' => '/etc/audit/auditd.conf',
                'line'  => 'max_log_file = 16',
                'match' => '^max_log_file =',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('auditd_max_log_size')
          end
        }
      end
    end
  end
end

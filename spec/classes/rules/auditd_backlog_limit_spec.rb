# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_backlog_limit' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              auditd: {
                'backlog_limit' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'backlog_limit' => 8192,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_kernel_parameter('audit_backlog_limit')
              .with(
                'ensure' => 'present',
                'value' => '8192',
              )
          else
            is_expected.not_to contain_kernel_parameter('audit_backlog_limit')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_log_config' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                action_mail_acct: 'none',
                admin_space_left_action: 'none',
                space_left_action: 'none',
                disk_full_action: 'none'
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
            is_expected.to contain_file('/etc/audit/auditd.conf')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0640',
              )

            is_expected.to contain_file_line('auditd log group')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/audit/auditd.conf',
                'match'              => '^log_group =',
                'line'               => 'log_group = root',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file('/etc/audit/auditd.conf')
            is_expected.not_to contain_file_line('auditd log group')
          end
        }
      end
    end
  end
end

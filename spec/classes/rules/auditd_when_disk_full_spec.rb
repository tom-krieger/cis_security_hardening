# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_when_disk_full' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
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
            'space_left_action' => 'email',
            'action_mail_acct' => 'root',
            'admin_space_left_action' => 'halt',
            'disk_full_action' => 'halt'
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('auditd_space_left_action')
              .with(
                'line'  => 'space_left_action = email',
                'path'  => '/etc/audit/auditd.conf',
                'match' => '^space_left_action',
              )

            is_expected.to contain_file_line('auditd_action_mail_acct')
              .with(
                'line'  => 'action_mail_acct = root',
                'path'  => '/etc/audit/auditd.conf',
                'match' => '^action_mail_acct',
              )

            is_expected.to contain_file_line('auditd_admin_space_left_action')
              .with(
                'line'  => 'admin_space_left_action = halt',
                'path'  => '/etc/audit/auditd.conf',
                'match' => '^admin_space_left_action',
              )
            is_expected.to contain_file_line('disk_full_action')
              .with(
                'line'  => 'disk_full_action = halt',
                'path'  => '/etc/audit/auditd.conf',
                'match' => '^disk_full_action',
              )
          else
            is_expected.not_to contain_file_line('auditd_space_left_action')
            is_expected.not_to contain_file_line('auditd_action_mail_acct')
            is_expected.not_to contain_file_line('auditd_admin_space_left_action')
            is_expected.not_to contain_file_line('disk_full_action')
          end
        }
      end
    end
  end
end

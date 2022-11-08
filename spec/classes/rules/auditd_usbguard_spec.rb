# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_usbguard' do
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
            is_expected.to contain_file_line('auditd_usbguard')
              .with(
                'line'  => 'AuditBackend=LinuxAudit',
                'path'  => '/etc/usbguard/usbguard-daemon.conf',
                'match' => '^AuditBackend=',
              )
          else
            is_expected.not_to contain_file_line('auditd_usbguard')
          end
        }
      end
    end
  end
end

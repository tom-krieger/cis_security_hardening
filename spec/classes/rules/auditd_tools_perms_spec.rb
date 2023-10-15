# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_tools_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                uid_min: '1000',
                auditing_process: 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'user' => 'root',
            'group' => 'root',
            'mode' => '0755',
            'tools' => ['/sbin/auditctl', '/sbin/aureport', '/sbin/auditd', '/sbin/augenrules', '/sbin/ausearch', '/sbin/autrace'],
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/sbin/auditctl')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0755',
              )

            is_expected.to contain_file('/sbin/aureport')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0755',
              )
            is_expected.to contain_file('/sbin/auditd')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0755',
              )
            is_expected.to contain_file('/sbin/augenrules')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0755',
              )
            is_expected.to contain_file('/sbin/ausearch')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0755',
              )
            is_expected.to contain_file('/sbin/autrace')
              .with(
                'ensure' => 'file',
                'owner' => 'root',
                'group' => 'root',
                'mode' => '0755',
              )
          else
            is_expected.not_to contain_file('/sbin/auditctl')
            is_expected.not_to contain_file('/sbin/aureport')
            is_expected.not_to contain_file('/sbin/auditd')
            is_expected.not_to contain_file('/sbin/augenrules')
            is_expected.not_to contain_file('/sbin/ausearch')
            is_expected.not_to contain_file('/sbin/autrace')
          end
        }
      end
    end
  end
end

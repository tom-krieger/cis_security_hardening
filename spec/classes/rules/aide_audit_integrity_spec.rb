# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::aide_audit_integrity' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'tools' => {
              '/sbin/auditctl' => 'p+i+n+u+g+s+b+acl+xattrs+sha512',
              '/sbin/auditd' => 'p+i+n+u+g+s+b+acl+xattrs+sha512',
              '/sbin/ausearch' => 'p+i+n+u+g+s+b+acl+xattrs+sha512',
            },
          }
        end

        it {
          is_expected.to compile.with_all_deps

          if enforce
            is_expected.to contain_file_line('aide tool /sbin/auditctl')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => '/etc/aide.conf',
                'line'               => '/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/auditctl',
              )
            is_expected.to contain_file_line('aide tool /sbin/auditd')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => '/etc/aide.conf',
                'line'               => '/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/auditd',
              )
            is_expected.to contain_file_line('aide tool /sbin/ausearch')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => '/etc/aide.conf',
                'line'               => '/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/ausearch',
              )
          else
            is_expected.not_to contain_file_line('aide tool /sbin/auditctl')
            is_expected.not_to contain_file_line('aide tool /sbin/auditd')
            is_expected.not_to contain_file_line('aide tool /sbin/ausearch')
          end
        }
      end
    end
  end
end

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
              '/sbin/aureport' => 'p+i+n+u+g+s+b+acl+xattrs+sha512',
              '/sbin/autrace' => 'p+i+n+u+g+s+b+acl+xattrs+sha512',
              '/sbin/augenrules' => 'p+i+n+u+g+s+b+acl+xattrs+sha512',
            },
          }
        end

        it {
          is_expected.to compile.with_all_deps

          if enforce
            conffile = if os_facts[:os]['name'].casecmp('rocky').zero?
                         '/etc/aide.conf'
                       elsif os_facts[:os]['name'].casecmp('ubuntu').zero?
                         if os_facts[:os]['release']['major'] >= '20'
                           '/etc/aide/aide.conf'
                         else
                           '/etc/aide.conf'
                         end
                       else
                         '/etc/aide.conf'
                       end

            is_expected.to contain_file_line('aide tool /sbin/auditctl')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => conffile,
                'line'               => '/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/auditctl',
              )
            is_expected.to contain_file_line('aide tool /sbin/auditd')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => conffile,
                'line'               => '/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/auditd',
              )
            is_expected.to contain_file_line('aide tool /sbin/ausearch')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => conffile,
                'line'               => '/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/ausearch',
              )
            is_expected.to contain_file_line('aide tool /sbin/aureport')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => conffile,
                'line'               => '/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/aureport',
              )
            is_expected.to contain_file_line('aide tool /sbin/autrace')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => conffile,
                'line'               => '/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/autrace',
              )
            is_expected.to contain_file_line('aide tool /sbin/augenrules')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => conffile,
                'line'               => '/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512',
                'match'              => '^/sbin/augenrules',
              )
          else
            is_expected.not_to contain_file_line('aide tool /sbin/auditctl')
            is_expected.not_to contain_file_line('aide tool /sbin/auditd')
            is_expected.not_to contain_file_line('aide tool /sbin/ausearch')
            is_expected.not_to contain_file_line('aide tool /sbin/aureport')
            is_expected.not_to contain_file_line('aide tool /sbin/autrace')
            is_expected.not_to contain_file_line('aide tool /sbin/augenrules')
          end
        }
      end
    end
  end
end

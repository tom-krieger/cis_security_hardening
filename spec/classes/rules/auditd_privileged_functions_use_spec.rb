# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_privileged_functions_use' do
  test_on = {
    hardwaremodels: ['x86_64', 'i686'],
  }

  let(:pre_condition) do
    <<-EOF
    class {'cis_security_hardening::rules::auditd_init':
      rules_file => '/etc/audit/rules.d/cis_security_hardening.rules',
    }

    class { 'cis_security_hardening::reboot':
      auto_reboot => true,
      time_until_reboot => 120,
    }
    EOF
  end

  on_supported_os(test_on).each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and arch ?= #{os_facts[:os]['architecture']}" do
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
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] == '7'
              if ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch privileged_functions command rule 3')
                  .with(
                    'order'   => '191',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid',
                  )
                is_expected.to contain_concat__fragment('watch privileged_functions command rule 4')
                  .with(
                    'order'   => '192',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid',
                  )
              else
                is_expected.to contain_concat__fragment('watch privileged_functions command rule 1')
                  .with(
                    'order'   => '189',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid',
                  )
                is_expected.to contain_concat__fragment('watch privileged_functions command rule 2')
                  .with(
                    'order'   => '190',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid',
                  )
              end
            elsif ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
              is_expected.to contain_concat__fragment('watch privileged_functions command rule 3')
                .with(
                    'order'   => '191',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv',
                  )
              is_expected.to contain_concat__fragment('watch privileged_functions command rule 4')
                .with(
                  'order'   => '192',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv',
                )
            else
              is_expected.to contain_concat__fragment('watch privileged_functions command rule 1')
                .with(
                  'order'   => '189',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv',
                )
              is_expected.to contain_concat__fragment('watch privileged_functions command rule 2')
                .with(
                  'order'   => '190',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv',
                )
            end
          else
            is_expected.not_to contain_concat__fragment('watch privileged_functions command rule 1')
            is_expected.not_to contain_concat__fragment('watch privileged_functions command rule 2')
            is_expected.not_to contain_concat__fragment('watch privileged_functions command rule 3')
            is_expected.not_to contain_concat__fragment('watch privileged_functions command rule 4')
          end
        }
      end
    end
  end
end

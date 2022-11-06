# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_kernel_modules' do
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

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and arch = #{os_facts[:os]['architecture']}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                delete: false,
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
            auid = if os_facts[:os]['name'].casecmp('rocky').zero? || os_facts[:os]['name'].casecmp('almalinux').zero?
                     'unset'
                   else
                     '4294967295'
                   end
            if os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] == '7'
              is_expected.to contain_concat__fragment('watch kernel modules rule 1')
                .with(
                  'order' => '204',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => "-a always,exit -S all -F path=/usr/bin/kmod -p x -F auid>=1000 -F auid!=#{auid} -k module-change",
                )
            else
              is_expected.to contain_concat__fragment('watch kernel modules rule 1')
                .with(
                  'order' => '204',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=#{auid} -F key=kernel_modules",
                )
            end

            if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
              is_expected.to contain_concat__fragment('watch kernel modules rule 2')
                .with(
                  'order' => '205',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=#{auid} -k kernel_modules",
                )

            else
              is_expected.not_to contain_concat__fragment('watch kernel modules rule 2')
            end
          else
            is_expected.not_to contain_concat__fragment('watch kernel modules rule 1')
            is_expected.not_to contain_concat__fragment('watch kernel modules rule 2')
          end
        }
      end
    end
  end
end

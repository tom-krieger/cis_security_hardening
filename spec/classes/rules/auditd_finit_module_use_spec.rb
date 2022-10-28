# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_finit_module_use' do
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
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce} and arch = #{arch}" do
          let(:facts) do
            os_facts.merge!(
              architecture: arch.to_s,
              cis_security_hardening: {
                auditd: {
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
              if os_facts[:operatingsystem].casecmp('redhat').zero? && os_facts[:operatingsystemmajrelease] == '7'
                if ['x86_64', 'amd64'].include?(arch)
                  is_expected.to contain_concat__fragment('watch finit_module command rule 2')
                    .with(
                      'order'   => '188',
                      'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-a always,exit -F arch=b64 -S finit_module -k module-change',
                    )
                else
                  is_expected.to contain_concat__fragment('watch finit_module command rule 1')
                    .with(
                      'order'   => '187',
                      'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-a always,exit -F arch=b32 -S finit_module -k module-change',
                    )
                end
              elsif ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch finit_module command rule 2')
                  .with(
                      'order'   => '188',
                      'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng',
                    )
              else
                is_expected.to contain_concat__fragment('watch finit_module command rule 1')
                  .with(
                    'order'   => '187',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b32 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng',
                  )
              end
            else
              is_expected.not_to contain_concat__fragment('watch finit_module command rule 1')
              is_expected.not_to contain_concat__fragment('watch finit_module command rule 2')
            end
          }
        end
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_modules' do
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

  test_on = {
    hardwaremodels: ['x86_64', 'i686'],
  }

  on_supported_os(test_on).each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and arch = #{os_facts[:os]['architecture']}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                modules: false,
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
            is_expected.to contain_concat__fragment('watch modules rule 1')
              .with(
                'order' => '71',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => '-w /sbin/insmod -p x -k modules',
              )

            is_expected.to contain_concat__fragment('watch modules rule 2')
              .with(
                'order' => '72',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => '-w /sbin/rmmod -p x -k modules',
              )

            is_expected.to contain_concat__fragment('watch modules rule 3')
              .with(
                'order' => '73',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => '-w /sbin/modprobe -p x -k modules',
              )

            if os_facts[:os]['family'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] >= '9'
              if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
                is_expected.to contain_concat__fragment('watch modules rule 4')
                  .with(
                    'order' => '74',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S init_module -S delete_module -F key=modules',
                  )
              end

              is_expected.to contain_concat__fragment('watch modules rule 5')
                .with(
                  'order' => '75',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S init_module -S delete_module -F key=modules',
                )
            else
              if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
                is_expected.to contain_concat__fragment('watch modules rule 4')
                  .with(
                    'order' => '74',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
                  )
              end

              is_expected.to contain_concat__fragment('watch modules rule 5')
                .with(
                  'order' => '75',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules',
                )
            end
          else
            is_expected.not_to contain_concat__fragment('watch modules rule 1')
            is_expected.not_to contain_concat__fragment('watch modules rule 2')
            is_expected.not_to contain_concat__fragment('watch modules rule 3')
            is_expected.not_to contain_concat__fragment('watch modules rule 4')
          end
        }
      end
    end
  end
end

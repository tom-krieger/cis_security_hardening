# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_kernel_modules' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce} and arch = #{arch}" do
          let(:pre_condition) do
            <<-EOF
            class {'cis_security_hardening::rules::auditd_init':
              rules_file => '/etc/audit/rules.d/cis_security_hardening.rules',
            }

            reboot { 'after_run':
              timeout => 60,
              message => 'forced reboot by Puppet',
              apply   => 'finished',
            }
            EOF
          end
          let(:facts) do
            os_facts.merge!(
              architecture: arch.to_s,
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
              auid = if os_facts[:operatingsystem].casecmp('rocky').zero?
                       'unset'
                     else
                       '4294967295'
                     end
              is_expected.to contain_concat__fragment('watch kernel modules rule 1')
                .with(
                  'order' => '204',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=#{auid} -F key=kernel_modules",
                )

              if ['x86_64', 'amd64'].include?(arch)
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
end

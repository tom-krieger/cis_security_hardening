# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_modules' do
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

              if ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch modules rule 4')
                  .with(
                    'order' => '74',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
                  )
              else
                is_expected.to contain_concat__fragment('watch modules rule 4')
                  .with(
                    'order' => '74',
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
end

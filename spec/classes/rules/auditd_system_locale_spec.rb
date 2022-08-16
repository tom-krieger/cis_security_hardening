# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_system_locale' do
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
                  'system-locale' => false,
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
              is_expected.to contain_concat__fragment('watch network environment rule 1')
                .with(
                  'order' => '131',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale',
                )

              is_expected.to contain_concat__fragment('watch network environment rule 2')
                .with(
                  'order' => '132',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/issue -p wa -k system-locale',
                )

              is_expected.to contain_concat__fragment('watch network environment rule 3')
                .with(
                  'order' => '133',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/issue.net -p wa -k system-locale',
                )

              is_expected.to contain_concat__fragment('watch network environment rule 4')
                .with(
                  'order' => '134',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/hosts -p wa -k system-locale',
                )

              if os_facts[:osfamily].casecmp('debian').zero?
                is_expected.to contain_concat__fragment('watch network environment rule 5')
                  .with(
                    'order' => '135',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-w /etc/network -p wa -k system-locale',
                  )
              else
                is_expected.to contain_concat__fragment('watch network environment rule 5')
                  .with(
                    'order' => '135',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-w /etc/sysconfig/network -p wa -k system-locale',
                  )
              end

              if os_facts[:operatingsystem].casecmp('rocky').zero?
                is_expected.to contain_concat__fragment('watch network environment rule 6')
                  .with(
                    'order' => '135',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-w /etc/sysconfig/network-scripts/ -p wa -k system-locale',
                  )
              end

              if ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch network environment rule 7')
                  .with(
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
                  )
              else
                is_expected.not_to contain_concat__fragment('watch network environment rule 7')
              end
            else
              is_expected.not_to contain_concat__fragment('watch network environment rule 1')
              is_expected.not_to contain_concat__fragment('watch network environment rule 2')
              is_expected.not_to contain_concat__fragment('watch network environment rule 3')
              is_expected.not_to contain_concat__fragment('watch network environment rule 4')
              is_expected.not_to contain_concat__fragment('watch network environment rule 5')
              is_expected.not_to contain_concat__fragment('watch network environment rule 7')
            end
          }
        end
      end
    end
  end
end

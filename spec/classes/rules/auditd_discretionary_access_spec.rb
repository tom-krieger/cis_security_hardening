# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_discretionary_access' do
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
              is_expected.to contain_concat__fragment('watch discretionary access control rule 1')
                .with(
                  'order' => '198',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod',
                )

              is_expected.to contain_concat__fragment('watch discretionary access control rule 2')
                .with(
                  'order' => '199',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod',
                )

              is_expected.to contain_concat__fragment('watch discretionary access control rule 3')
                .with(
                  'order' => '200',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod',
                )

              if ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch discretionary access control rule 4')
                  .with(
                    'order' => '201',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod',
                  )
                is_expected.to contain_concat__fragment('watch discretionary access control rule 5')
                  .with(
                    'order' => '202',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod',
                  )
                is_expected.to contain_concat__fragment('watch discretionary access control rule 6')
                  .with(
                    'order' => '203',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod',
                  )
              else
                is_expected.not_to contain_concat__fragment('watch discretionary access control rule 4')
                is_expected.not_to contain_concat__fragment('watch discretionary access control rule 5')
                is_expected.not_to contain_concat__fragment('watch discretionary access control rule 6')
              end
            else
              is_expected.not_to contain_concat__fragment('watch discretionary access control rule 1')
              is_expected.not_to contain_concat__fragment('watch discretionary access control rule 2')
              is_expected.not_to contain_concat__fragment('watch discretionary access control rule 3')
              is_expected.not_to contain_concat__fragment('watch discretionary access control rule 4')
              is_expected.not_to contain_concat__fragment('watch discretionary access control rule 5')
              is_expected.not_to contain_concat__fragment('watch discretionary access control rule 6')
            end
          }
        end
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_perm_mod' do
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
                  uid_min: '1000',
                  'perm-mod' => false,
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
              is_expected.to contain_concat__fragment('watch perm mod rule 1')
                .with(
                  'order' => '91',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                )

              is_expected.to contain_concat__fragment('watch perm mod rule 2')
                .with(
                  'order' => '92',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                )

              is_expected.to contain_concat__fragment('watch perm mod rule 3')
                .with(
                  'order' => '93',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                )

              if ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch perm mod rule 4')
                  .with(
                    'order' => '94',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                  )

                is_expected.to contain_concat__fragment('watch perm mod rule 5')
                  .with(
                    'order' => '95',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                  )

                is_expected.to contain_concat__fragment('watch perm mod rule 6')
                  .with(
                    'order' => '96',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
                  )

              else
                is_expected.not_to contain_concat__fragment('watch perm mod rule 4')
                is_expected.not_to contain_concat__fragment('watch perm mod rule 5')
                is_expected.not_to contain_concat__fragment('watch perm mod rule 6')
              end
            else
              is_expected.not_to contain_concat__fragment('watch perm mod rule 1')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 2')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 3')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 4')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 5')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 6')
            end
          }
        end
      end
    end
  end
end

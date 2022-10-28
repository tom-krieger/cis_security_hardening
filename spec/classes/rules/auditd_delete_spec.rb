# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_delete' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce} and arch = #{arch}" do
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
          let(:facts) do
            os_facts.merge!(
              architecture: arch.to_s,
              cis_security_hardening: {
                auditd: {
                  uid_min: '1000',
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
              auid = if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
                       'unset'
                     else
                       '4294967295'
                     end
              content_rule1 = if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
                                "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=#{auid} -k delete"
                              else
                                "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=#{auid} -k delete"
                              end

              is_expected.to contain_concat__fragment('watch deletes rule 1')
                .with(
                  'order' => '31',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule1,
                )

              if ['x86_64', 'amd64'].include?(arch)
                content_rule2 = if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
                                  "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=#{auid} -k delete"
                                else
                                  "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=#{auid} -k delete"
                                end

                is_expected.to contain_concat__fragment('watch deletes rule 2')
                  .with(
                    'order' => '32',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => content_rule2,
                  )

              else
                is_expected.not_to contain_concat__fragment('watch deletes rule 2')
              end
            else
              is_expected.not_to contain_concat__fragment('watch deletes rule 1')
              is_expected.not_to contain_concat__fragment('watch deletes rule 2')
            end
          }
        end
      end
    end
  end
end

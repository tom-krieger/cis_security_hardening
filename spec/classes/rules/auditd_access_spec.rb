# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_access' do
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
                  access: false,
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

              content_rule1 = if os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?
                                "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=#{auid} -k access"
                              elsif os_facts[:operatingsystem].casecmp('redhat').zero?
                                "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=#{auid} -k perm_access"
                              else
                                "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=#{auid} -k access"
                              end

              content_rule2 = if os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?
                                "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=#{auid} -k access"
                              elsif os_facts[:operatingsystem].casecmp('redhat').zero?
                                "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=#{auid} -k perm_access"
                              else
                                "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=#{auid} -k access"
                              end

              is_expected.to contain_concat__fragment('watch access rule 1')
                .with(
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule1,
                  'order'   => '11',
                )
              is_expected.to contain_concat__fragment('watch access rule 2')
                .with(
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule2,
                  'order'   => '12',
                )

              if ['x86_64', 'amd64'].include?(arch)
                content_rule3 = if os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?
                                  "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=#{auid} -k access"
                                elsif os_facts[:operatingsystem].casecmp('redhat').zero?
                                  "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=#{auid} -k perm_access"
                                else
                                  "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=#{auid} -k access"
                                end

                content_rule4 = if os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?
                                  "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=#{auid} -k access"
                                elsif os_facts[:operatingsystem].casecmp('redhat').zero?
                                  "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=#{auid} -k perm_access"
                                else
                                  "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=#{auid} -k access"
                                end

                is_expected.to contain_concat__fragment('watch access rule 3')
                  .with(
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => content_rule3,
                    'order'   => '13',
                  )
                is_expected.to contain_concat__fragment('watch access rule 4')
                  .with(
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => content_rule4,
                    'order'   => '14',
                  )
              else
                is_expected.not_to contain_concat__fragment('watch access rule 3')
                is_expected.not_to contain_concat__fragment('watch access rule 4')
              end
            else
              is_expected.not_to contain_concat__fragment('watch access rule 1')
              is_expected.not_to contain_concat__fragment('watch access rule 2')
              is_expected.not_to contain_concat__fragment('watch access rule 3')
              is_expected.not_to contain_concat__fragment('watch access rule 4')
            end
          }
        end
      end
    end
  end
end

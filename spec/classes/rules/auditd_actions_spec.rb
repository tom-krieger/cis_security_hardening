# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_actions' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce} and arch = #{arch} and major = #{os_facts[:operatingsystemmajrelease]}" do
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
                  scope: false,
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

              if os_facts[:operatingsystem].casecmp('redhat').zero? || os_facts[:operatingsystem].casecmp('centos').zero? ||
                 os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?

                if os_facts[:operatingsystemmajrelease] >= '8'

                  is_expected.to contain_concat__fragment('watch admin actions rule 1')
                    .with(
                      'order' => '21',
                      'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-w /var/log/sudo.log -p wa -k actions',
                    )

                else

                  if ['x86_64', 'amd64'].include?(arch)
                    is_expected.to contain_concat__fragment('watch admin actions rule 1')
                      .with(
                        'order' => '21',
                        'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                        'content' => '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions',
                      )
                  end

                  is_expected.to contain_concat__fragment('watch admin actions rule 2')
                    .with(
                      'order' => '22',
                      'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions',
                    )
                end

              elsif os_facts[:operatingsystem].casecmp('ubuntu').zero?

                if ['x86_64', 'amd64'].include?(arch)
                  is_expected.to contain_concat__fragment('watch admin actions rule 1')
                    .with(
                      'order' => '21',
                      'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-a exit,always -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions',
                    )
                end

                is_expected.to contain_concat__fragment('watch admin actions rule 2')
                  .with(
                    'order' => '22',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -F key=actions',
                  )

              elsif os_facts[:operatingsystem].casecmp('debian').zero?

                is_expected.to contain_concat__fragment('watch admin actions rule 1')
                  .with(
                      'order' => '21',
                      'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                      'content' => '-w /var/log/sudo.log -p wa -k actions',
                    )

              end

            else
              is_expected.not_to contain_concat__fragment('watch admin actions rule 1')
              is_expected.not_to contain_concat__fragment('watch admin actions rule 2')
            end
          }
        end
      end
    end
  end
end

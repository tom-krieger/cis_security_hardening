# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_actions' do
  test_on = {
    hardwaremodels: ['x86_64', 'i686'],
  }

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

  on_supported_os(test_on).each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} and arch = #{os_facts[:os]['architecture']} and major = #{os_facts[:os]['release']['major']}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                uid_min: 1000,
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

            if os_facts[:os]['name'].casecmp('redhat').zero? || os_facts[:os]['name'].casecmp('centos').zero? ||
               os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?

              if os_facts[:os]['release']['major'] >= '8'

                is_expected.to contain_concat__fragment('watch admin actions rule 1')
                  .with(
                    'order' => '21',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-w /var/log/sudo.log -p wa -k actions',
                  )

              else

                if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
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

            elsif os_facts[:os]['name'].casecmp('ubuntu').zero?

              if os_facts[:os]['release']['major'] >= '20'
                is_expected.to contain_concat__fragment('watch admin actions rule 1')
                  .with(
                    'order'   => 21,
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-w /var/log/sudo.log -p wa -k sudo_log_file',
                  )
              else
                if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
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

            elsif os_facts[:os]['name'].casecmp('debian').zero?

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

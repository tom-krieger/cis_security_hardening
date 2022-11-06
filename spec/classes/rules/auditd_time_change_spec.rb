# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_time_change' do

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
      context "on #{os} with enforce = #{enforce} and arch = #{os_facts[:os]['architecture']}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                'time-change' => false,
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
            if os_facts[:os]['name'].casecmp('rocky').zero? || os_facts[:os]['name'].casecmp('almalinux').zero?
              is_expected.to contain_concat__fragment('watch for date-time-change rule 1')
                .with(
                  'order' => '121',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change',
                )
              is_expected.to contain_concat__fragment('watch for date-time-change rule 3')
                .with(
                  'order' => '123',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/localtime -p wa -k time-change',
                )
              if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
                is_expected.to contain_concat__fragment('watch for date-time-change rule 2')
                  .with(
                    'order' => '122',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change',
                  )
              else
                is_expected.not_to contain_concat__fragment('watch for date-time-change rule 2')
              end
            else
              is_expected.to contain_concat__fragment('watch for date-time-change rule 1')
                .with(
                  'order' => '121',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
                )

              is_expected.to contain_concat__fragment('watch for date-time-change rule 2')
                .with(
                  'order' => '122',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S clock_settime -k time-change',
                )

              is_expected.to contain_concat__fragment('watch for date-time-change rule 3')
                .with(
                  'order' => '123',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/localtime -p wa -k time-change',
                )

              if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
                is_expected.to contain_concat__fragment('watch for date-time-change rule 4')
                  .with(
                    'order' => '124',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
                  )

                is_expected.to contain_concat__fragment('watch for date-time-change rule 5')
                  .with(
                    'order' => '125',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S clock_settime -k time-change',
                  )

              else
                is_expected.not_to contain_concat__fragment('watch for date-time-change rule 4')
                is_expected.not_to contain_concat__fragment('watch for date-time-change rule 5')
              end
            end

          else
            is_expected.not_to contain_concat__fragment('watch for date-time-change rule 1')
            is_expected.not_to contain_concat__fragment('watch for date-time-change rule 2')
            is_expected.not_to contain_concat__fragment('watch for date-time-change rule 3')
            is_expected.not_to contain_concat__fragment('watch for date-time-change rule 4')
            is_expected.not_to contain_concat__fragment('watch for date-time-change rule 5')
          end
        }
      end
    end
  end
end

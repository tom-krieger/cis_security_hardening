# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_system_locale' do
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
                uid_min: '1000',
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
            content_rule1 = if os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?
                              '-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale'
                            else
                              '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale'
                            end
            is_expected.to contain_concat__fragment('watch network environment rule 1')
              .with(
                'order' => '131',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => content_rule1,
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

            if os_facts[:os]['family'].casecmp('debian').zero?
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

            if os_facts[:os]['name'].casecmp('rocky').zero? || os_facts[:os]['name'].casecmp('almalinux').zero?
              is_expected.to contain_concat__fragment('watch network environment rule 6')
                .with(
                  'order' => '135',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/sysconfig/network-scripts -p wa -k system-locale',
                )
            end

            if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
              content_rule7 = if os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?
                                '-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale'
                              else
                                '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale'
                              end
              is_expected.to contain_concat__fragment('watch network environment rule 7')
                .with(
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule7,
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

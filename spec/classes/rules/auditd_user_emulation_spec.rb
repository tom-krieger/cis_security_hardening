# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_user_emulation' do
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
            is_expected.to contain_concat__fragment('watch user emulation rule 1')
              .with(
                'order' => '196',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => '-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -k user_emulation',
              )

            if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
              is_expected.to contain_concat__fragment('watch user emulation rule 2')
                .with(
                  'order' => '197',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=unset -k user_emulation',
                )
            end
          else
            is_expected.not_to contain_concat__fragment('watch user emulation rule 1')
            is_expected.not_to contain_concat__fragment('watch user emulation rule 2')
          end
        }
      end
    end
  end
end

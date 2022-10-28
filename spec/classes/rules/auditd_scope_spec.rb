# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_scope' do
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
              is_expected.to contain_concat__fragment('watch scope rule 1')
                .with(
                  'order' => '101',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/sudoers -p wa -k scope',
                )

              is_expected.to contain_concat__fragment('watch scope rule 2')
                .with(
                  'order' => '102',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/sudoers.d/ -p wa -k scope',
                )

            else
              is_expected.not_to contain_concat__fragment('watch scope rule 1')
              is_expected.not_to contain_concat__fragment('watch scope rule 2')
            end
          }
        end
      end
    end
  end
end

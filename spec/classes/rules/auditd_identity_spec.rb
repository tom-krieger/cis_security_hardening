# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_identity' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |_arch|
        context "on #{os}" do
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
              cis_security_hardening: {
                auditd: {
                  uid_min: '1000',
                  identity: false,
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
              is_expected.to contain_concat__fragment('watch identity rule 1')
                .with(
                  'order' => '41',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/group -p wa -k identity',
                )

              is_expected.to contain_concat__fragment('watch identity rule 2')
                .with(
                  'order' => '42',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/passwd -p wa -k identity',
                )

              unless os_facts[:operatingsystem].casecmp('sles').zero?
                is_expected.to contain_concat__fragment('watch identity rule 3')
                  .with(
                    'order' => '43',
                    'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-w /etc/gshadow -p wa -k identity',
                  )
              end

              is_expected.to contain_concat__fragment('watch identity rule 4')
                .with(
                  'order' => '44',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/shadow -p wa -k identity',
                )

              is_expected.to contain_concat__fragment('watch identity rule 5')
                .with(
                  'order' => '45',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/security/opasswd -p wa -k identity',
                )
            else
              is_expected.not_to contain_concat__fragment('watch identity rule 1')
              is_expected.not_to contain_concat__fragment('watch identity rule 2')
              is_expected.not_to contain_concat__fragment('watch identity rule 3')
              is_expected.not_to contain_concat__fragment('watch identity rule 4')
              is_expected.not_to contain_concat__fragment('watch identity rule 5')
            end
          }
        end
      end
    end
  end
end

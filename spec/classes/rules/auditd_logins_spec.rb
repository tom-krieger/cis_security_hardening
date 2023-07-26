# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_logins' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
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
          os_facts.merge(
            cis_security_hardening: {
              auditd: {
                logins: false,
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

            is_expected.to contain_concat__fragment('logins policy rule 1')
              .with(
                'order' => '51',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => '-w /var/log/lastlog -p wa -k logins',
              )

            if os_facts[:os]['family'].casecmp('redhat').zero?

              is_expected.to contain_concat__fragment('logins policy rule 2')
                .with(
                  'order' => '52',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /var/run/faillock/ -p wa -k logins',
                )

              is_expected.not_to contain_concat__fragment('logins policy rule 3')

            elsif os_facts[:os]['family'].casecmp('redhat').zero? || os_facts[:os]['family'].casecmp('suse').zero?

              is_expected.to contain_concat__fragment('logins policy rule 2')
                .with(
                  'order' => '52',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /var/log/faillog -p wa -k logins',
                )

              is_expected.to contain_concat__fragment('logins policy rule 3')
                .with(
                  'order' => '53',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /var/log/tallylog -p wa -k logins',
                )

            end

          else
            is_expected.not_to contain_concat__fragment('logins policy rule 1')
            is_expected.not_to contain_concat__fragment('logins policy rule 2')
            is_expected.not_to contain_concat__fragment('logins policy rule 3')
          end
        }
      end
    end
  end
end

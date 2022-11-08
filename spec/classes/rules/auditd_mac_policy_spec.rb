# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_mac_policy' do
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
                uid_min: '1000',
                'mac-policy' => false,
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
            if os_facts[:os]['family'].casecmp('redhat').zero? || os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_concat__fragment('mac policy rule 1')
                .with(
                  'order' => '61',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/selinux/ -p wa -k MAC-policy',
                )

              is_expected.to contain_concat__fragment('mac policy rule 2')
                .with(
                  'order' => '62',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /usr/share/selinux/ -p wa -k MAC-policy',
                )
            elsif os_facts[:os]['family'].casecmp('debian').zero?
              is_expected.to contain_concat__fragment('mac policy rule 1')
                .with(
                  'order' => '61',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/apparmor/ -p wa -k MAC-policy',
                )

              is_expected.to contain_concat__fragment('mac policy rule 2')
                .with(
                  'order' => '62',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-w /etc/apparmor.d/ -p wa -k MAC-policy',
                )
            end
          else
            is_expected.not_to contain_concat__fragment('mac policy rule 1')
            is_expected.not_to contain_concat__fragment('mac policy rule 2')
          end
        }
      end
    end
  end
end

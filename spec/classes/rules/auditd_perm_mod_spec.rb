# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_perm_mod' do
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
                'perm-mod' => false,
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
              auid = 'unset'
              content_rule1 = "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule2 = "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule3 = "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule4 = "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule5 = "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule6 = "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=#{auid} -k perm_mod"
            else
              auid = '4294967295'
              content_rule1 = "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule2 = "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule3 = "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule4 = "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule5 = "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=#{auid} -k perm_mod"
              content_rule6 = "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=#{auid} -k perm_mod"
            end

            is_expected.to contain_concat__fragment('watch perm mod rule 1')
              .with(
                'order' => '91',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => content_rule1,
              )

            is_expected.to contain_concat__fragment('watch perm mod rule 2')
              .with(
                'order' => '92',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => content_rule2,
              )

            is_expected.to contain_concat__fragment('watch perm mod rule 3')
              .with(
                'order' => '93',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => content_rule3,
              )

            if ['x86_64', 'amd64'].include?(os_facts[:os]['architecture'])
              is_expected.to contain_concat__fragment('watch perm mod rule 4')
                .with(
                  'order' => '94',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule4,
                )

              is_expected.to contain_concat__fragment('watch perm mod rule 5')
                .with(
                  'order' => '95',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule5,
                )

              is_expected.to contain_concat__fragment('watch perm mod rule 6')
                .with(
                  'order' => '96',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => content_rule6,
                )

            else
              is_expected.not_to contain_concat__fragment('watch perm mod rule 4')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 5')
              is_expected.not_to contain_concat__fragment('watch perm mod rule 6')
            end
          else
            is_expected.not_to contain_concat__fragment('watch perm mod rule 1')
            is_expected.not_to contain_concat__fragment('watch perm mod rule 2')
            is_expected.not_to contain_concat__fragment('watch perm mod rule 3')
            is_expected.not_to contain_concat__fragment('watch perm mod rule 4')
            is_expected.not_to contain_concat__fragment('watch perm mod rule 5')
            is_expected.not_to contain_concat__fragment('watch perm mod rule 6')
          end
        }
      end
    end
  end
end

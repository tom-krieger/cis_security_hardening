# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
reboot_options = [true, false]

describe 'cis_security_hardening::rules::auditd_init' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      reboot_options.each do |reboot|
        context "on #{os} with enforce = #{enforce} and reboot = #{reboot}" do
          let(:pre_condition) do
            <<-EOF
            reboot { 'after_run':
              timeout => 60,
              message => 'forced reboot by Puppet',
              apply   => 'finished',
            }
            EOF
          end
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce' => enforce,
              'buffer_size' => 8192,
              'rules_file' => '/etc/audit/rules.d/cis_security_hardening.rules',
              'auto_reboot' => reboot,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if reboot
                is_expected.to contain_concat('/etc/audit/rules.d/cis_security_hardening.rules')
                  .with(
                    'ensure' => 'present',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0640',
                    'ensure_newline' => true,
                  )
                  .that_notifies(['Exec[reload auditd rules]', 'Reboot[after_run]'])
              else
                is_expected.to contain_concat('/etc/audit/rules.d/cis_security_hardening.rules')
                  .with(
                    'ensure' => 'present',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0640',
                    'ensure_newline' => true,
                  )
                  .that_notifies(['Exec[reload auditd rules]'])
              end

              is_expected.to contain_file('/etc/audisp')
                .with(
                  'ensure' => 'directory',
                  'owner'  => 'root',
                  'group'  => 'root',
                  'mode'   => '0755',
                )

              is_expected.to contain_concat__fragment('auditd init delete rules')
                .with(
                  'order' => '01',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-D',
                )

              is_expected.to contain_concat__fragment('auditd init set buffer')
                .with(
                  'order' => '02',
                  'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-b 8192',
                )
            else
              is_expected.not_to contain_file('/etc/audit/rules.d/cis_security_hardening.rules')
              is_expected.not_to contain_concat__fragment('auditd init delete rules')
              is_expected.not_to contain_concat__fragment('auditd init set buffer')
              is_expected.not_to contain_file('/etc/audisp')
            end

            is_expected.to contain_exec('reload auditd rules')
              .with(
                'refreshonly' => true,
                'command'     => 'auditctl -R /etc/audit/rules.d/cis_security_hardening.rules',
                'path'        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
              )
          }
        end
      end
    end
  end
end

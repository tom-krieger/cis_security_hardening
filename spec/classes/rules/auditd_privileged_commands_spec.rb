# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_privileged_commands' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce} and arch = #{arch}" do
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
              architecture: arch.to_s,
              cis_security_hardening: {
                auditd: {
                  'priv-cmds' => false,
                  'priv-cmds-list' => ['/usr/bin/fusermount', '/usr/bin/passwd'],
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
              is_expected.to contain_concat__fragment('priv. commands rules')
                .with(
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'order'   => '350',
                )
                
              # is_expected.to contain_file('/etc/audit/rules.d/cis_security_hardening_priv_cmds.rules')
              #   .with(
              #     'ensure'  => 'file',
              #     'owner'   => 'root',
              #     'group'   => 'root',
              #     'mode'    => '0640',
              #   )
              #   .that_notifies('Exec[reload auditd rules priv cmds]')

              # is_expected.to contain_exec('reload auditd rules priv cmds')
              #   .with(
              #     'refreshonly' => true,
              #     'command'     => 'auditctl -R /etc/audit/rules.d/cis_security_hardening_priv_cmds.rules',
              #     'path'        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
              #   )
            else
              is_expected.not_to contain_concat__fragment('priv. commands rules')
              # is_expected.not_to contain_exec('reload auditd rules priv cmds')
            end
          }
        end
      end
    end
  end
end

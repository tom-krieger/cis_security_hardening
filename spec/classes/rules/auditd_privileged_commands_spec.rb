# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_privileged_commands' do

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
  
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
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

            is_expected.to contain_file('/etc/audit/rules.d/cis_security_hardening_priv_cmds.rules')
              .with(
                'ensure'  => 'absent',
              )
          else
            is_expected.not_to contain_concat__fragment('priv. commands rules')
          end
        }
      end
    end
  end
end

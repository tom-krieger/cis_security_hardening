# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
arch_options = ['x86_64', 'i686']

describe 'cis_security_hardening::rules::auditd_rmdir' do
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

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      arch_options.each do |arch|
        context "on #{os} with enforce = #{enforce}" do
          let(:facts) do
            os_facts.merge!(
              architecture: arch.to_s,
              cis_security_hardening: {
                auditd: {
                  uid_min: '1000',
                  auditing_process: 'none',
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
              is_expected.to contain_concat__fragment('watch rmdir rule 1')
                .with(
                  'order'   => '210',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete',
                )

              if ['x86_64', 'amd64'].include?(arch)
                is_expected.to contain_concat__fragment('watch rmdir rule 2')
                  .with(
                    'order'   => '211',
                    'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                    'content' => '-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete',
                  )

              end
            else
              is_expected.not_to contain_concat__fragment('watch rmdir rule 1')
              is_expected.not_to contain_concat__fragment('watch rmdir rule 2')
            end
          }
        end
      end
    end
  end
end

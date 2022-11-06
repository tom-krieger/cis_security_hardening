# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_failure_processing' do
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
                immutable: false,
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
            is_expected.to contain_concat__fragment('failure_processing')
              .with(
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'order' => '998',
                'content' => '-f 2',
              )
          else
            is_expected.not_to contain_concat__fragment('failure_processing')
          end
        }
      end
    end
  end
end

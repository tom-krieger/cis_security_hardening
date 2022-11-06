# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_sudoers' do
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
            is_expected.to contain_concat__fragment('watch sudoers rule 1')
              .with(
                'order' => '218',
                'target' => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => '-w /etc/sudoers -p wa -k identity',
              )
          else
            is_expected.not_to contain_concat__fragment('watch sudoers rule 1')
          end
        }
      end
    end
  end
end

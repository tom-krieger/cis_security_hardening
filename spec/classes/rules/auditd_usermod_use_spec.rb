# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_usermod_use' do
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
          os_facts.merge!(
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
            auid = if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
                     'unset'
                   else
                     '4294967295'
                   end
            is_expected.to contain_concat__fragment('watch usermod command rule 1')
              .with(
                'order'   => '184',
                'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                'content' => "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=#{auid} -k privileged-usermod",
              )
          else
            is_expected.not_to contain_concat__fragment('watch usermod command rule 1')
          end
        }
      end
    end
  end
end

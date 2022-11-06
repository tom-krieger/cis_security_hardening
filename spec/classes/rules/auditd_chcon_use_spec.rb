# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_chcon_use' do
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
            auid = if os_facts[:os]['name'].casecmp('rocky').zero? || os_facts[:os]['name'].casecmp('almalinux').zero?
                     'unset'
                   else
                     '4294967295'
                   end
            if os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] == '7'
              is_expected.to contain_concat__fragment('watch chcon command rule 1')
                .with(
                  'order'   => '176',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => "-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=#{auid} -k privileged-priv_change",
                )
            else
              is_expected.to contain_concat__fragment('watch chcon command rule 1')
                .with(
                  'order'   => '176',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=#{auid} -k perm_chng",
                )
            end
          else
            is_expected.not_to contain_concat__fragment('watch chcon command rule 1')
          end
        }
      end
    end
  end
end

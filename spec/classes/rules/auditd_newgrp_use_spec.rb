# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_newgrp_use' do
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
            if os_facts[:operatingsystem].casecmp('redhat').zero? && os_facts[:operatingsystemmajrelease] == '7'
              is_expected.to contain_concat__fragment('watch newgrp command rule 1')
                .with(
                  'order'   => '175',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change',
                )
            else
              is_expected.to contain_concat__fragment('watch newgrp command rule 1')
                .with(
                  'order'   => '175',
                  'target'  => '/etc/audit/rules.d/cis_security_hardening.rules',
                  'content' => '-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd',
                )
            end
          else
            is_expected.not_to contain_concat__fragment('watch newgrp command rule 1')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_overflow_action' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          service { 'auditd':
            ensure => running,
            enable => true,
          }
          EOF
        end
        let(:facts) do
          os_facts.merge!(
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
            'action' => 'halt',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('overflow-action')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/audisp/audispd.conf',
                'match'  => '^overflow_action =',
                'line'   => 'overflow_action = halt',
              )
              .that_notifies('Service[auditd]')

          else
            is_expected.not_to contain_file_line('overflow-action')
          end
        }
      end
    end
  end
end

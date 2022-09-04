# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_remote_labeled' do
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
            'format' => 'fqd',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('name-format')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/audisp/audispd.conf',
                'match'  => '^name_format =',
                'line'   => 'name_format = fqd',
              )
              .that_notifies('Service[auditd]')

          else
            is_expected.not_to contain_file_line('name-format')
          end
        }
      end
    end
  end
end

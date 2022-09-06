# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_remote_conf' do
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
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/audisp/plugins.d/au-remote.conf')
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_file_line('off-load-direction')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/audisp/plugins.d/au-remote.conf',
                'match'  => '^direction =',
                'line'   => 'direction = out',
              )
              .that_notifies('Service[auditd]')

            is_expected.to contain_file_line('off-load-path')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/audisp/plugins.d/au-remote.conf',
                'match'  => '^path =',
                'line'   => 'path = /sbin/audisp-remote',
              )
              .that_notifies('Service[auditd]')

            is_expected.to contain_file_line('off-load-type')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/audisp/plugins.d/au-remote.conf',
                'match'  => '^type =',
                'line'   => 'type = always',
              )
              .that_notifies('Service[auditd]')

          else
            is_expected.not_to contain_file_line('off-load-direction')
            is_expected.not_to contain_file_line('off-load-path')
            is_expected.not_to contain_file_line('off-load-type')
          end
        }
      end
    end
  end
end

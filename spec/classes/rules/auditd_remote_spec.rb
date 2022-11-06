# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_remote' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'remote_server' => '10.10.10.10',
          }
        end

        it {
          is_expected.to compile

          if enforce
            file = if os_facts[:os]['family'].casecmp('redhat').zero?
                     '/etc/audisp/audisp-remote.conf'
                   else
                     '/etc/audisp/plugins.d/au-remote.conf'
                   end
            is_expected.to contain_file_line('auditd log remote')
              .with(
                'ensure'             => 'present',
                'path'               => file,
                'line'               => 'active = yes',
                'match'              => '^active =',
                'append_on_no_match' => true,
              )

            is_expected.to contain_file_line('auditd log remote server')
              .with(
                'ensure'             => 'present',
                'path'               => file,
                'line'               => 'remote_server = 10.10.10.10',
                'match'              => '^remote_server = 10.10.10.10',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('auditd log remote')
            is_expected.not_to contain_file_line('auditd log remote server')
          end
        }
      end
    end
  end
end

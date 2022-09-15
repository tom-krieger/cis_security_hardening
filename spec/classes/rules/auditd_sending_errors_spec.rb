# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::auditd_sending_errors' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'action' => 'halt',
          }
        end

        it {
          is_expected.to compile

          if enforce
            file = if os_facts[:osfamily].casecmp('redhat').zero?
                     '/etc/audisp/audisp-remote.conf'
                   else
                     '/etc/audisp/plugins.d/au-remote.conf'
                   end
            is_expected.to contain_file(file)
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0644',
              )

            is_expected.to contain_file_line('network-failure-action')
              .with(
                'ensure'             => 'present',
                'path'               => file,
                'match'              => '^network_failure_acrion =',
                'line'               => 'network_failure_action = halt',
                'append_on_no_match' => true,
              )
              .that_requires("File[#{file}]")

          else
            is_expected.not_to contain_file('/etc/audisp/audisp-remote.conf')
            is_expected.not_to contain_file_line('network-failure-action')
          end
        }
      end
    end
  end
end

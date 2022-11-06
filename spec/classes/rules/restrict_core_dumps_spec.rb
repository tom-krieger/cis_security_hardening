# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::restrict_core_dumps' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'systemd-coredump' => 'yes',
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
            is_expected.to contain_file('/etc/security/limits.d/50-restrict-coredumps.conf')
              .with(
                'ensure'  => 'file',
                'content' => '*          hard    core     0',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
              )
            is_expected.to contain_sysctl('fs.suid_dumpable').with('value' => 0)

            if os_facts[:os]['family'].casecmp('redhat').zero? || os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.to contain_file_line('systemd-coredump-storage')
                .with(
                  'path' => '/etc/systemd/coredump.conf',
                  'line' => 'Storage=none',
                )
              is_expected.to contain_file_line('systemd-coredump-process-max')
                .with(
                  'path' => '/etc/systemd/coredump.conf',
                  'line' => 'ProcessSizeMax=0',
                )
            end
          else
            is_expected.not_to contain_file('/etc/security/limits.d/50-restrict-coredumps.conf')
            is_expected.not_to contain_sysctl('fs.suid_dumpable')
            is_expected.not_to contain_file_line('systemd-coredump-storage')
            is_expected.not_to contain_file_line('systemd-coredump-process-max')
          end
        }
      end
    end
  end
end

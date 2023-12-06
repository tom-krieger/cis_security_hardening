# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::auditd_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'using defaults' do
        let(:params) do
          {
            'dirs_to_include' => ['/usr'],
            'start_time_minute' => 40,
            'start_time_hour' => 4,
            'cron_repeat' => '2',
            'output_file' => '/usr/share/cis_security_hardening/data/auditd_priv_cmds.txt',
            'script' => '/usr/share/cis_security_hardening/bin/auditd_priv_cmds.sh',
          }
        end

        it do
          is_expected.to compile.with_all_deps

          is_expected.to contain_file('/etc/cron.d/auditd_priv_commands.cron')
            .with(
              'ensure' => 'absent',
            )

          is_expected.to contain_file('/etc/cron.d/auditd_priv_commands')
            .with(
              'ensure'  => 'file',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0644',
            )

          is_expected.to contain_file('/usr/share/cis_security_hardening/bin/auditd_priv_cmds.sh')
            .with(
              'ensure'  => 'file',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0700',
            )
        end
      end

      context 'absent' do
        let(:params) do
          {
            'ensure' => 'absent',
            'dirs_to_include' => ['/usr'],
            'start_time_minute' => 40,
            'start_time_hour' => 4,
            'cron_repeat' => '2',
            'output_file' => '/usr/share/cis_security_hardening/data/auditd_priv_cmds.txt',
            'script' => '/usr/share/cis_security_hardening/bin/auditd_priv_cmds.sh',
          }
        end

        it do
          is_expected.to compile.with_all_deps

          is_expected.to contain_file('/etc/cron.d/auditd_priv_commands.cron')
            .with(
              'ensure' => 'absent',
            )

          is_expected.to contain_file('/etc/cron.d/auditd_priv_commands')
            .with(
              'ensure'  => 'absent',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0644',
            )

          is_expected.to contain_file('/usr/share/cis_security_hardening/bin/auditd_priv_cmds.sh')
            .with(
              'ensure'  => 'absent',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0700',
            )
        end
      end
    end
  end
end

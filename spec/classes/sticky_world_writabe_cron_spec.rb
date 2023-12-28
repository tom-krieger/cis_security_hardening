# frozen_string_literal: true

require 'spec_helper'

describe 'cis_security_hardening::sticky_world_writable_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'using defaults' do
        let(:params) do
          {
            'dirs_to_exclude' => [],
            'filename'        => '/usr/share/cis_security_hardening/data/world-writable-files.txt',
            'script'          => '/usr/share/cis_security_hardening/bin/sticy-world-writable.sh',
          }
        end

        it do
          is_expected.to compile.with_all_deps

          is_expected.to contain_file('/usr/share/cis_security_hardening/bin/sticy-world-writable.sh')
            .with(
              'ensure'  => 'file',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0700',
            )

          is_expected.to contain_file('/etc/cron.d/sticky-world-writebale.cron')
            .with(
              'ensure' => 'absent',
            )

          is_expected.to contain_file('/etc/cron.d/sticky-world-writebale')
            .with(
              'ensure'  => 'file',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0644',
            )
        end
      end

      context 'absent' do
        let(:params) do
          {
            'ensure' => 'absent',
            'dirs_to_exclude' => [],
            'filename'        => '/usr/share/cis_security_hardening/data/world-writable-files.txt',
            'script'          => '/usr/share/cis_security_hardening/bin/sticy-world-writable.sh',
          }

        it do
          is_expected.to compile.with_all_deps

          is_expected.to contain_file('/usr/share/cis_security_hardening/bin/sticy-world-writable.sh')
            .with(
              'ensure'  => 'absent',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0700',
            )

          is_expected.to contain_file('/etc/cron.d/sticky-world-writebale.cron')
            .with(
              'ensure' => 'absent',
            )

          is_expected.to contain_file('/etc/cron.d/sticky-world-writebale')
            .with(
              'ensure'  => 'absent',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0644',
            )
        end
      end
    end
  end
end

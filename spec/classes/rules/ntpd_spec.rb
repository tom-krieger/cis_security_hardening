# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ntpd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        describe 'without ntp servers defined' do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce'       => enforce,
              'ntp_servers'   => [],
              'ntp_statsdir'  => '/var/tmp',
              'ntp_driftfile' => '/var/lib/ntp/drift',
              'ntp_restrict'  => ['127.0.0.1'],
            }
          end

          if enforce && !os_facts[:os]['name'].casecmp('sles').zero?
            it {
              is_expected.to compile
              is_expected.to create_class('ntp')
            }
          end
        end

        describe 'with ntp servers defined' do
          let(:facts) { os_facts }
          let(:params) do
            {
              'enforce'       => enforce,
              'ntp_servers'   => ['10.10.10.1', '10.10.10.2'],
              'ntp_statsdir'  => '/var/tmp',
              'ntp_driftfile' => '/var/lib/ntp/drift',
              'ntp_restrict'  => ['127.0.0.1'],
            }
          end

          it {
            is_expected.to compile

            if enforce && !os_facts[:os]['name'].casecmp('sles').zero?

              is_expected.to create_class('ntp')
                .with(
                  'servers'         => ['10.10.10.1', '10.10.10.2'],
                  'restrict'        => ['127.0.0.1'],
                  'statsdir'        => '/var/tmp',
                  'driftfile'       => '/var/lib/ntp/drift',
                  'disable_monitor' => true,
                  'iburst_enable'   => false,
                  'service_manage'  => true,
                )

              if os_facts[:os]['family'].casecmp('debian').zero?
                is_expected.to contain_package('chrony')
                  .with(
                    'ensure' => 'purged',
                  )
                is_expected.to contain_service('systemd-timesyncd')
                  .with(
                    'ensure' => 'stopped',
                    'enable' => false,
                  )

                is_expected.to contain_file_line('ntp runas')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/init.d/ntp',
                    'match'  => '^RUNASUSER=',
                    'line'   =>  'RUNASUSER=ntp',
                  )

              else
                is_expected.not_to contain_service('systemd-timesyncd')
                is_expected.to contain_file('/etc/sysconfig/ntpd')
                  .with(
                    'ensure'  => 'file',
                    'owner'   => 'root',
                    'group'   => 'root',
                    'mode'    => '0644',
                    'content' => 'OPTIONS="-u ntp:ntp"',
                  )
              end
            else
              is_expected.not_to create_class('ntp')
              is_expected.not_to contain_file('/etc/sysconfig/ntpd')
              is_expected.not_to contain_package('chrony')
              is_expected.not_to contain_service('systemd-timesyncd')
            end
          }
        end
      end
    end
  end
end

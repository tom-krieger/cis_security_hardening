# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
fix_perms_options = [true, false]

describe 'cis_security_hardening::rules::systemd_timesyncd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      fix_perms_options.each do |fix_perms|
        context "on #{os} with enforce = #{enforce} and fix_perms = #{fix_perms}" do
          let(:facts) do
            os_facts.merge(
              cis_security_hardening: {
                services_enabled: {
                  'systemd-timesyncd' => 'disabled',
                },
              },
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
              'fix_file_perms' => fix_perms,
              'ntp_servers' => ['0.de.pool.ntp.org', '1.de.pool.ntp.org', '2.de.pool.ntp.org'],
              'ntp_fallback_servers' => ['3.de.pool.ntp.org'],
            }
          end

          it {
            is_expected.to compile

            if enforce
              is_expected.to contain_file_line('ntp-timesyncd.conf')
                .with(
                  'path'               => '/etc/systemd/timesyncd.conf',
                  'line'               => 'NTP=0.de.pool.ntp.org 1.de.pool.ntp.org 2.de.pool.ntp.org',
                  'match'              => '^NTP=',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('ntp-fallback-timesyncd.conf')
                .with(
                  'path'               => '/etc/systemd/timesyncd.conf',
                  'line'               => 'FallbackNTP=3.de.pool.ntp.org',
                  'match'              => '^FallbackNTP=',
                  'append_on_no_match' => true,
                )

              if os_facts[:os]['family'].casecmp('suse').zero?
                is_expected.to contain_package('ntp')
                  .with(
                    'ensure' => 'absent',
                  )

                is_expected.to contain_package('chrony')
                  .with(
                    'ensure' => 'absent',
                  )
              else
                is_expected.to contain_package('ntp')
                  .with(
                    'ensure' => 'purged',
                  )

                is_expected.to contain_package('chrony')
                  .with(
                    'ensure' => 'purged',
                  )
              end

              is_expected.to contain_service('systemd-timesyncd.service')
                .with(
                  'enable' => true,
                  'ensure' => 'running',
                )

              if os_facts[:os]['name'].casecmp('sles').zero?
                is_expected.to contain_exec('timedatectl')
                  .with(
                    'command'   => 'timefdatectl set-ntp true',
                    'path'      => ['/bin', '/usr/bin'],
                  )
              end

              if os_facts[:os]['family'].casecmp('debian').zero? && fix_perms == true
                is_expected.to contain_file('/var/lib/private/systemd/timesync')
                  .with(
                    'owner' => 'root',
                    'group' => 'root',
                  )
                is_expected.to contain_file('/var/lib/private/systemd/timesync/clock')
                  .with(
                    'owner' => 'root',
                    'group' => 'root',
                  )
              else
                is_expected.not_to contain_file('/var/lib/private/systemd/timesync')
                is_expected.not_to contain_file('/var/lib/private/systemd/timesync/clock')
              end
            else
              is_expected.not_to contain_file_line('ntp-timesyncd.conf')
              is_expected.not_to contain_file_line('ntp-fallback-timesyncd.conf')
              is_expected.not_to contain_package('ntp')
              is_expected.not_to contain_package('chrony')
              is_expected.not_to contain_file('/var/lib/private/systemd/timesync')
              is_expected.not_to contain_file('/var/lib/private/systemd/timesync/clock')
            end
          }
        end
      end
    end
  end
end

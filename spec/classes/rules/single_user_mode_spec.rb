# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::single_user_mode' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context "on Redhat with enforce #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:os]['family'].casecmp('redhat').zero?

              if os_facts[:os]['release']['major'].to_s == '6'

                is_expected.to contain_file_line('sulogin')
                  .with(
                    'path'  => '/etc/sysconfig/init',
                    'line'  => 'SINGLE=/sbin/sulogin',
                    'match' => '^SINGLE=',
                    'append_on_no_match' => true,
                  )

              elsif os_facts[:os]['release']['major'].to_s == '7'

                is_expected.to contain_file_line('su-rescue')
                  .with(
                    'path'  => '/usr/lib/systemd/system/rescue.service',
                    'line'  => 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
                    'match' => '^ExecStart=',
                  )

                is_expected.to contain_file_line('su-emergency')
                  .with(
                    'path'  => '/usr/lib/systemd/system/emergency.service',
                    'line'  => 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
                    'match' => '^ExecStart=',
                  )

              else

                is_expected.to contain_file_line('su-rescue')
                  .with(
                    'path'  => '/usr/lib/systemd/system/rescue.service',
                    'line'  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue',
                    'match' => '^ExecStart=',
                  )

                is_expected.to contain_file_line('su-emergency')
                  .with(
                    'path'  => '/usr/lib/systemd/system/emergency.service',
                    'line'  => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency',
                    'match' => '^ExecStart=',
                  )
              end

            elsif os_facts[:os]['family'].casecmp('suse').zero?

              is_expected.to contain_file_line('modify resuce')
                .with(
                  'ensure'             => 'present',
                  'path'               => '/usr/lib/systemd/system/rescue.service',
                  'match'              => '^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell',
                  'line'               => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescure',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('modify emergency')
                .with(
                  'ensure'             => 'present',
                  'path'               => '/usr/lib/systemd/system/emergency.service',
                  'match'              => '^ExecStart=-/usr/lib/systemd/systemd-sulogin-shell',
                  'line'               => 'ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency',
                  'append_on_no_match' => true,
                )
            end

          else
            is_expected.not_to contain_file_line('su-rescue')
            is_expected.not_to contain_file_line('su-emergency')
            is_expected.not_to contain_file_line('sulogin')
            is_expected.not_to contain_file_line('modify resuce')
            is_expected.not_to contain_file_line('modify emergency')
          end
        }
      end
    end
  end
end

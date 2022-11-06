# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
reboot_options = [true, false]

describe 'cis_security_hardening::rules::crypto_policy' do
  let(:pre_condition) do
    <<-EOF
    class { 'cis_security_hardening::reboot':
      auto_reboot => true,
      time_until_reboot => 120,
    }
    EOF
  end

  on_supported_os.each do |_os, os_facts|
    reboot_options.each do |reboot|
      enforce_options.each do |enforce|
        context "RedHat with enforce = #{enforce} and policy FUTURE and reboot = #{reboot}" do
          let(:facts) do
            os_facts.merge!(
              'cis_security_hardening' => {
                'crypto_policy' => {
                  'legacy' => 'LEGACY',
                  'policy' => 'DEFAULT',
                  'fips_mode' => 'enabled',
                },
              },
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
              'crypto_policy' => 'FUTURE',
              'auto_reboot' => reboot,
            }
          end

          it {
            is_expected.to compile

            if enforce &&
               (os_facts[:os]['name'].casecmp('centos').zero? ||
               os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?) &&
               (os_facts[:os]['release']['major'] >= '8')

              if reboot
                is_expected.to contain_exec('set crypto policy to FUTURE (current: DEFAULT)')
                  .with(
                    'command' => 'update-crypto-policies --set FUTURE',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                    'onlyif'  => "test -z \"\$(update-crypto-policies --show | grep FUTURE)\"",
                  )
                  .that_notifies('Reboot[after_run]')

                is_expected.to contain_exec('set FIPS to disable')
                  .with(
                    'command' => 'fips-mode-setup --disable',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  )
                  .that_notifies('Reboot[after_run]')
              else
                is_expected.to contain_exec('set crypto policy to FUTURE (current: DEFAULT)')
                  .with(
                    'command' => 'update-crypto-policies --set FUTURE',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                    'onlyif'  => "test -z \"\$(update-crypto-policies --show | grep FUTURE)\"",
                  )

                is_expected.to contain_exec('set FIPS to disable')
                  .with(
                    'command' => 'fips-mode-setup --disable',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  )
              end

            else
              is_expected.not_to contain_exec('set crypto policy to FUTURE (current: DEFAULT)')
              is_expected.not_to contain_exec('set FIPS to disable')
            end
          }
        end

        context "RedHat with enforce = #{enforce} and policy FIPS and reboot = #{reboot}" do
          let(:facts) do
            os_facts.merge!(
              'cis_security_hardening' => {
                'crypto_policy' => {
                  'legacy' => 'LEGACY',
                  'policy' => 'DEFAULT',
                  'fips_mode' => 'disabled',
                },
              },
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
              'crypto_policy' => 'FIPS',
              'auto_reboot' => reboot,
            }
          end

          it {
            is_expected.to compile

            if enforce &&
               (os_facts[:os]['name'].casecmp('centos').zero? ||
               os_facts[:os]['name'].casecmp('almalinux').zero? ||
               os_facts[:os]['name'].casecmp('rocky').zero?) &&
               (os_facts[:os]['release']['major'] >= '8')

              if reboot
                is_expected.to contain_exec('set crypto policy to FIPS (current: DEFAULT)')
                  .with(
                    'command' => 'update-crypto-policies --set FIPS',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  )
                  .that_notifies('Reboot[after_run]')

                is_expected.to contain_exec('set FIPS to enable')
                  .with(
                    'command' => 'fips-mode-setup --enable',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  )
                  .that_notifies('Reboot[after_run]')
              else
                is_expected.to contain_exec('set crypto policy to FIPS (current: DEFAULT)')
                  .with(
                    'command' => 'update-crypto-policies --set FIPS',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  )

                is_expected.to contain_exec('set FIPS to enable')
                  .with(
                    'command' => 'fips-mode-setup --enable',
                    'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
                  )
              end

            else
              is_expected.not_to contain_exec('set crypto policy to FIPS (current: DEFAULT)')
              is_expected.not_to contain_exec('set FIPSto enable')
            end
          }
        end
      end
    end
  end
end

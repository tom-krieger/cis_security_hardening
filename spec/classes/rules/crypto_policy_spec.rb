# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::crypto_policy' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context "RedHat with enforce = #{enforce} and policy FUTURE" do
        let(:pre_condition) do
          <<-EOF
          reboot { 'after_run':
            timeout => 60,
            message => 'forced reboot by Puppet',
            apply   => 'finished',
          }
          EOF
        end
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
          }
        end

        it {
          is_expected.to compile

          if enforce &&
             (os_facts[:operatingsystem].casecmp('centos').zero? ||
             os_facts[:operatingsystem].casecmp('almalinux').zero? || os_facts[:operatingsystem].casecmp('rocky').zero?) &&
             (os_facts[:operatingsystemmajrelease] >= '8')

            is_expected.to contain_exec('set crypto policy to FUTURE (current: DEFAULT)')
              .with(
                'command' => 'update-crypto-policies --set FUTURE',
                'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
              )
              .that_notifies('Reboot[after_run]')

            is_expected.to contain_exec('set FIPS to disable')
              .with(
                'command' => 'fips-mode-setup --disable',
                'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
              )
              .that_notifies('Reboot[after_run]')
          else
            is_expected.not_to contain_exec('set crypto policy to FUTURE (current: DEFAULT)')
            is_expected.not_to contain_exec('set FIPS to disable')
          end
        }
      end

      context "RedHat with enforce = #{enforce} and policy FIPS" do
        let(:pre_condition) do
          <<-EOF
          reboot { 'after_run':
            timeout => 60,
            message => 'forced reboot by Puppet',
            apply   => 'finished',
          }
          EOF
        end
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
          }
        end

        it {
          is_expected.to compile

          if enforce &&
             (os_facts[:operatingsystem].casecmp('centos').zero? ||
             os_facts[:operatingsystem].casecmp('almalinux').zero? ||
             os_facts[:operatingsystem].casecmp('rocky').zero?) &&
             (os_facts[:operatingsystemmajrelease] >= '8')

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
            is_expected.not_to contain_exec('set crypto policy to FIPS (current: DEFAULT)')
            is_expected.not_to contain_exec('set FIPSto enable')
          end
        }
      end
    end
  end
end

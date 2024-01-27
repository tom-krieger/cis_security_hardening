# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::iptables_install' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce

            is_expected.to contain_resources('firewall')
              .with(
                'purge' => true,
              )

            if os_facts[:os]['name'].casecmp('ubuntu').zero? && os_facts[:os]['release']['major'] >= '20'
              is_expected.to contain_package('iptables-persist')
                .with(
                  'ensure' => 'installed',
                )
            end

            if os_facts[:os]['name'].casecmp('redhat').zero? || os_facts[:os]['name'].casecmp('centos').zero? ||
               os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?

              if os_facts[:os]['name'].casecmp('almalinux').zero? || os_facts[:os]['name'].casecmp('rocky').zero?
                is_expected.to contain_package('nftables')
                  .with(
                    'ensure' => 'installed',
                  )

                is_expected.to contain_service('nftables')
                  .with(
                    'ensure' => 'running',
                    'enable' => true,
                  )
              else
                is_expected.to contain_package('nftables')
                  .with(
                    'ensure' => 'purged',
                  )

                is_expected.to contain_service('nftables')
                  .with(
                    'ensure' => 'stopped',
                    'enable' => false,
                  )
              end

              is_expected.to contain_package('firewalld')
                .with(
                  'ensure' => 'purged',
                )

              is_expected.to contain_service('firewalld')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )

              if os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] > '7'
                is_expected.to contain_class('firewall')
                  .with(
                    'service_name' => ['iptables'],
                    'service_name_v6' => 'ip6tables',
                    'package_name' => ['iptables-services'],
                    'ensure_v6' => 'stopped',
                  )
              else
                is_expected.to contain_class('firewall')
              end

            elsif os_facts[:os]['name'].casecmp('ubuntu').zero?

              is_expected.to contain_package('ufw')
                .with(
                  'ensure' => 'purged',
                )
              is_expected.to contain_package('nftables')
                .with(
                  'ensure' => 'purged',
                )
            elsif os_facts[:os]['name'].casecmp('sles').zero?

              is_expected.to contain_package('firewalld')
                .with(
                  'ensure' => 'absent',
                )
              is_expected.to contain_package('nftables')
                .with(
                  'ensure' => 'absent',
                )
            end

          else
            is_expected.not_to contain_class('::firewall')
            is_expected.not_to contain_resources('firewall')
            is_expected.not_to contain_package('ufw')
            is_expected.not_to contain_package('nftables')
            is_expected.not_to contain_service('firewalld')
            is_expected.not_to contain_service('nftables')
            is_expected.not_to contain_package('firewalld')
            is_expected.not_to contain_package('nftables')
            is_expected.not_to contain_package('firewalld')
          end
        }
      end
    end
  end
end

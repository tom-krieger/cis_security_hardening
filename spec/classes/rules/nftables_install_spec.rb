# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_install' do
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
            if os_facts[:os]['name'].casecmp('sles').zero?
              is_expected.to contain_package('firewalld')
                .with(
                  'ensure' => 'absent',
                )
            elsif os_facts[:os]['name'].casecmp('centos').zero? && os_facts[:os]['release']['major'] > '7'
              is_expected.to contain_package('firewalld')
                .with(
                  'ensure' => 'purged',
                )
            else

              is_expected.to contain_package('iptables-services')
                .with(
                'ensure' => 'purged',
              )

              is_expected.to contain_package('firewalld')
                .with(
                  'ensure' => 'purged',
                )
            end

            is_expected.to contain_package('nftables')
              .with(
                'ensure' => 'installed',
              )

            unless os_facts[:os]['name'].casecmp('centos').zero? && os_facts[:os]['release']['major'] > '7'
              is_expected.to contain_service('iptables')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_service('ip6tables')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
            end

            is_expected.to contain_service('nftables')
              .with(
                'ensure' => 'running',
                'enable' => true,
              )
            if os_facts[:os]['name'].casecmp('ubuntu').zero?
              is_expected.to contain_package('ufw')
                .with(
                  'ensure' => 'purged',
                )
            end
          else
            is_expected.not_to contain_package('nftables')
            is_expected.not_to contain_package('iptables-services')
            is_expected.not_to contain_package('firewalld')
            is_expected.not_to contain_service('iptables')
            is_expected.not_to contain_service('ip6tables')
            is_expected.not_to contain_service('nftables')
            is_expected.not_to contain_package('ufw')
          end
        }
      end
    end
  end
end

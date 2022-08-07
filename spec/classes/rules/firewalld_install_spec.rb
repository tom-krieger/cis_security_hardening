# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::firewalld_install' do
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
            if os_facts[:operatingsystem].casecmp('sles').zero?
              is_expected.to contain_package('iptables')
                .with(
                  'ensure' => 'present',
                )
              is_expected.to contain_package('nftables')
                .with(
                  'ensure' => 'absent',
                )
            else
              is_expected.to contain_package('iptables-services')
                .with(
                  'ensure' => 'purged',
                )
              is_expected.to contain_package('nftables')
                .with(
                  'ensure' => 'purged',
                )
            end

            is_expected.to contain_package('firewalld')
              .with(
                'ensure' => 'present',
              )
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
            is_expected.to contain_service('nftables')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
          else
            is_expected.not_to contain_package('firewalld')
            is_expected.not_to contain_package('iptables')
            is_expected.not_to contain_package('nftables')
            is_expected.not_to contain_package('iptables-services')
            is_expected.not_to contain_service('iptables')
            is_expected.not_to contain_service('ip6tables')
            is_expected.not_to contain_service('nftables')
          end
        }
      end
    end
  end
end

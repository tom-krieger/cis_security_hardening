# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::icmp_redirects' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} without ipv6" do
        my_facts = os_facts.reject { |k| k == 'network6' }
        let(:facts) { my_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_sysctl('net.ipv4.conf.all.accept_redirects')
              .with(
                'value' => 0,
              )
            is_expected.to contain_sysctl('net.ipv4.conf.default.accept_redirects')
              .with(
                'value' => 0,
              )
          else
            is_expected.not_to contain_sysctl('net.ipv4.conf.all.accept_redirects')
            is_expected.not_to contain_sysctl('net.ipv4.conf.default.accept_redirects')
            is_expected.not_to contain_sysctl('net.ipv6.conf.all.accept_redirects')
            is_expected.not_to contain_sysctl('net.ipv6.conf.default.accept_redirects')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} with ipv6" do
        let(:facts) do
          os_facts.merge!(
            {
              'network6' => 'fe81::',
              'netmask6' => 'ffff:ffff:ffff:ffff::',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_sysctl('net.ipv4.conf.all.accept_redirects')
              .with(
                'value' => 0,
              )
            is_expected.to contain_sysctl('net.ipv4.conf.default.accept_redirects')
              .with(
                'value' => 0,
              )

            is_expected.to contain_sysctl('net.ipv6.conf.all.accept_redirects')
              .with(
                'value' => 0,
              )
            is_expected.to contain_sysctl('net.ipv6.conf.default.accept_redirects')
              .with(
                'value' => 0,
              )

          else
            is_expected.not_to contain_sysctl('net.ipv4.conf.all.accept_redirects')
            is_expected.not_to contain_sysctl('net.ipv4.conf.default.accept_redirects')
            is_expected.not_to contain_sysctl('net.ipv6.conf.all.accept_redirects')
            is_expected.not_to contain_sysctl('net.ipv6.conf.default.accept_redirects')
          end
        }
      end
    end
  end
end

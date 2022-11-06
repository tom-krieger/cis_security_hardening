# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_ipv6' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'network6' => '1.2.3.4',
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

            is_expected.to contain_kernel_parameter('ipv6.disable')
              .with(
                'value' => '1',
              )
            is_expected.to contain_sysctl('net.ipv6.conf.all.disable_ipv6')
              .with(
                'value' => '1',
              )
            is_expected.to contain_sysctl('net.ipv6.conf.default.disable_ipv6')
              .with(
                'value' => '1',
              )

          else
            is_expected.not_to contain_kernel_parameter('ipv6.disable')
            is_expected.not_to contain_sysctl('net.ipv6.conf.all.disable_ipv6')
            is_expected.not_to contain_sysctl('net.ipv6.conf.default.disable_ipv6')
          end
        }
      end
    end
  end
end

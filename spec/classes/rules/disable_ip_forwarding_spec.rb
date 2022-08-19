# frozen_string_literal: true

require 'spec_helper'
require 'pp'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_ip_forwarding' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'network6' => 'ff:ee:aa:bb:11:33',
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
            is_expected.to contain_sysctl('net.ipv4.ip_forward')
              .with(
                'value' => 0,
              )

            if os_facts.key?('network6')
              is_expected.to contain_sysctl('net.ipv6.conf.all.forwarding')
                .with(
                  'value' => 0,
                )
            end
          else
            is_expected.not_to contain_sysctl('net.ipv4.ip_forward')
            is_expected.not_to contain_sysctl('net.ipv6.conf.all.forwarding')
          end
        }
      end
    end
  end
end

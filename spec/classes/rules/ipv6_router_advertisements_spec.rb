# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
describe 'cis_security_hardening::rules::ipv6_router_advertisements' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge!(
            network6: 'fe80::',
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
            is_expected.to contain_sysctl('net.ipv6.conf.all.accept_ra')
              .with(
                'value' => 0,
              )
            is_expected.to contain_sysctl('net.ipv6.conf.default.accept_ra')
              .with(
                'value' => 0,
              )
          else
            is_expected.not_to contain_sysctl('net.ipv6.conf.all.accept_ra')
            is_expected.not_to contain_sysctl('net.ipv6.conf.default.accept_ra')
          end
        }
      end
    end
  end
end

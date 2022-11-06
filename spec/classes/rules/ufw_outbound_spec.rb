# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ufw_outbound' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              sservices_enabled: {
                srv_ufw: 'disabled',
              },
              ufw: {
                loopback_status: false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'firewall_rules' => {
              'allow DNS outbound' => {
                'queue' => 'out',
                'to' => 'any',
                'port' => '53',
                'proto' => 'udp',
                'action' => 'allow',
              },
              'allow http outbound' => {
                'queue' => 'out',
                'to' => 'any',
                'port' => '80',
                'proto' => 'tcp',
                'action' => 'allow',
              },
            },
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('allow DNS outbound')
              .with(
                'command' => 'ufw allow out to any port 53',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^53.*ALLOW out\')"',
              )
            is_expected.to contain_exec('allow http outbound')
              .with(
                'command' => 'ufw allow out to any port 80',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^80.*ALLOW out\')"',
              )
          else
            is_expected.not_to contain_exec('allow DNS outbound')
            is_expected.not_to contain_exec('allow http outbound')
          end
        }
      end
    end
  end
end

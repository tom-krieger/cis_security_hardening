# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ufw_open_ports' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              services_enabled: {
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
              'allow ssh' => {
                'queue' => 'in',
                'port' => '22',
                'proto' => 'tcp',
                'action' => 'allow',
                'from' => 'any',
                'to' => 'any',
              },
              'allow DNS inbound' => {
                'queue' => 'in',
                'port' => '53',
                'proto' => 'udp',
                'action' => 'allow',
                'from' => 'any',
                'to' => 'any',
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
            is_expected.to contain_exec('allow ssh')
              .with(
                'command' => 'ufw allow proto tcp from any to any port 22',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^22/tcp.*ALLOW in\')"',
              )
            is_expected.to contain_exec('allow DNS inbound')
              .with(
                'command' => 'ufw allow proto udp from any to any port 53',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(ufw status verbose | grep -E -i \'^53/udp.*ALLOW in\')"',
              )
          else
            is_expected.not_to contain_exec('allow ssh')
            is_expected.not_to contain_exec('allow DNS inbound')
          end
        }
      end
    end
  end
end

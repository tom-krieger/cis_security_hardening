# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::ufw_default_deny' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
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
            'default_incoming' => 'deny',
            'default_outgoing' => 'deny',
            'default_routed' => 'deny',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('default incoming policy deny')
              .with(
                'command' => 'ufw default deny incoming',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => "test -z \"$(ufw status verbose | grep 'deny (incoming)')\"",
              )

            is_expected.to contain_exec('default outgoing policy deny')
              .with(
                'command' => 'ufw default deny outgoing',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => "test -z \"$(ufw status verbose | grep 'deny (outgoing)')\"",
              )

            is_expected.to contain_exec('default routed policy deny')
              .with(
                'command' => 'ufw default deny routed',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => "test -z \"$(ufw status verbose | grep -e 'deny (routed)' -e 'disabled (routed)')\"",
              )
          else
            is_expected.not_to contain_exec('default incoming policy deny')
            is_expected.not_to contain_exec('default outgoing policy deny')
          end
        }
      end
    end
  end
end

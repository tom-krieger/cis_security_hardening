# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_wireless' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce} without nmcli" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'wlan_interfaces_count' => 1,
              'wlan_interfaces' => ['wlan1'],
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
            if os_facts[:osfamily].casecmp('redhat').zero?
              is_expected.to contain_package('NetworkManager')
                .with(
                  'ensure' => 'present',
                )
            elsif os_facts[:osfamily].casecmp('debian').zero?
              is_expected.to contain_package('network-manager')
                .with(
                  'ensure' => 'present',
                )
            end

            is_expected.to contain_exec('shutdown wlan interface wlan1')
              .with(
                'command' => 'ip link set wlan1 down',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
                'onlyif'  => "ip link show wlan1 | grep 'state UP'",
              )
          else
            is_expected.not_to contain_service('shutdown wlan interface wlan1')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} with nmcli" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'wlan_status' => 'enabled',
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
            is_expected.to contain_exec('switch radio off')
              .with(
                'command' => 'nmcli radio all off',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )
          else
            is_expected.not_to contain_service('switch radio off')
          end
        }
      end
    end
  end
end

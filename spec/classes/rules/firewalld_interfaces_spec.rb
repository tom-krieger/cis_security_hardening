# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::firewalld_interfaces' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'cis_security_hardening' => {
            'firewalld' => {
              'default_zone_status' => false,
              'zone_iface_assigned_status' => false,
              'zone_iface' => {
                'public' => 'eth1',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'zone_config' => {
            'public' => 'eth0',
          },
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_exec('firewalld change zone interface')
            .with(
              'command' => 'firewall-cmd --zone=public --change-interface=eth0',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
        else
          is_expected.not_to contain_exec('firewalld change zone interface')
        end
      }
    end
  end
end

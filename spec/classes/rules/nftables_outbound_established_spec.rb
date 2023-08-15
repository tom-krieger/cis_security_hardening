# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_outbound_established' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:pre_condition) do
        <<-EOF
        exec { 'dump nftables ruleset':
          command     => 'nft list ruleset > /etc/nftables/nftables.rules',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
        package { 'nftables':
          ensure => installed,
        }
        EOF
      end
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'cis_security_hardening' => {
            'nftables' => {
              'base_chain_input' => 'none',
              'base_chain_forward' => 'none',
              'base_chain_output' => 'none',
              'table_count' => 0,
              'table_count_status' => false,
              'base_chain_status' => false,
              'inet' => {
                'conns' => {
                  'status' => false,
                  'in_tcp' => false,
                  'in_udp' => false,
                  'in_icmp' => false,
                  'out_tcp' => false,
                  'out_udp' => false,
                  'out_icmp' => false,
                },
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'table' => 'inet',
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_exec('add nftables rule for input tcp established')
            .with(
              'command' => 'nft add rule inet filter input ip protocol tcp ct state established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'ip protocol tcp ct state established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('add nftables rule for input udp established')
            .with(
              'command' => 'nft add rule inet filter input ip protocol udp ct state established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'ip protocol udp ct state established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('add nftables rule for input icmp established')
            .with(
              'command' => 'nft add rule inet filter input ip protocol icmp ct state established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'ip protocol icmp ct state established accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('add nftables rule for output tcp established')
            .with(
              'command' => 'nft add rule inet filter output ip protocol tcp ct state new,related,established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'ip protocol tcp ct state established,related,new accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('add nftables rule for output udp established')
            .with(
              'command' => 'nft add rule inet filter output ip protocol udp ct state new,related,established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'ip protocol udp ct state established,related,new accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('add nftables rule for output icmp established')
            .with(
              'command' => 'nft add rule inet filter output ip protocol icmp ct state new,related,established accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset inet | grep \'ip protocol icmp ct state established,related,new accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
        else
          is_expected.not_to contain_exec('add nftables rule for input tcp established')
          is_expected.not_to contain_exec('add nftables rule for input udp established')
          is_expected.not_to contain_exec('add nftables rule for input icmp established')
          is_expected.not_to contain_exec('add nftables rule for output tcp established')
          is_expected.not_to contain_exec('add nftables rule for output udp established')
          is_expected.not_to contain_exec('add nftables rule for output icmp established')
        end
      }
    end
  end
end

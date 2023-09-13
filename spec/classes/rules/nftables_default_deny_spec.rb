# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_default_deny' do
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
          ensure => installes,
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
              'base_chain_status' => false,
              'table_count' => 0,
              'table_count_status' => false,
              'conns' => {
                'status' => false,
                'in_tcp' => false,
                'in_udp' => false,
                'in_icmp' => false,
                'out_tcp' => false,
                'out_udp' => false,
                'out_icmp' => false,
              },
              'inet' => {
                'policy' => {
                  'input' => 'accept',
                  'output' => 'accept',
                  'forward' => 'accept',
                  'status' => false,
                },
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'default_policy_input' => 'drop',
          'default_policy_forward' => 'drop',
          'default_policy_output' => 'drop',
          'table' => 'inet',
          'additional_rules' => {
            'input' => ['tcp dport ssh accept',
                        'tcp dport 22 accept',
                        'udp dport 123 accept',
                        'udp dport 53 accept'],
            'output' => ['tcp dport 21 accept',
                         'tcp dport 20 accept',
                         'tcp dport 443 accept',
                         'tcp dport 53 accept',
                         'tcp dport 80 accept',
                         'udp dport 123 accept',
                         'udp dport 53 accept'],
          },
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_exec('set input default policy')
            .with(
              'command' => 'nft chain inet filter input { policy drop \; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('set forward default policy')
            .with(
              'command' => 'nft chain inet filter forward { policy drop \; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('set output default policy')
            .with(
              'command' => 'nft chain inet filter output { policy drop \; }',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('adding rule input-tcp dport ssh accept')
            .with(
              'command' => 'nft add rule inet filter input tcp dport ssh accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter input | grep \'tcp dport ssh accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule input-tcp dport 22 accept')
            .with(
              'command' => 'nft add rule inet filter input tcp dport 22 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter input | grep \'tcp dport 22 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule input-udp dport 123 accept')
            .with(
              'command' => 'nft add rule inet filter input udp dport 123 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter input | grep \'udp dport 123 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule input-udp dport 53 accept')
            .with(
              'command' => 'nft add rule inet filter input udp dport 53 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter input | grep \'udp dport 53 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-tcp dport 21 accept')
            .with(
              'command' => 'nft add rule inet filter output tcp dport 21 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'tcp dport 21 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-tcp dport 20 accept')
            .with(
              'command' => 'nft add rule inet filter output tcp dport 20 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'tcp dport 20 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-tcp dport 443 accept')
            .with(
              'command' => 'nft add rule inet filter output tcp dport 443 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'tcp dport 443 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-tcp dport 53 accept')
            .with(
              'command' => 'nft add rule inet filter output tcp dport 53 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'tcp dport 53 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-tcp dport 80 accept')
            .with(
              'command' => 'nft add rule inet filter output tcp dport 80 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'tcp dport 80 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-udp dport 123 accept')
            .with(
              'command' => 'nft add rule inet filter output udp dport 123 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'udp dport 123 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
          is_expected.to contain_exec('adding rule output-udp dport 53 accept')
            .with(
              'command' => 'nft add rule inet filter output udp dport 53 accept',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list chain inet filter output | grep \'udp dport 53 accept\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
            .that_requires('Package[nftables]')
        else
          is_expected.not_to contain_exec('set input default policy')
          is_expected.not_to contain_exec('set forward default policy')
          is_expected.not_to contain_exec('set output default policy')
          is_expected.not_to contain_exec('adding rule tcp dport ssh accept')
          is_expected.not_to contain_exec('adding rule input-tcp dport 22 accept')
          is_expected.not_to contain_exec('adding rule input-udp dport 123 accept')
          is_expected.not_to contain_exec('adding rule input-udp dport 53 accept')
          is_expected.not_to contain_exec('adding rule output-tcp dport 21 accept')
          is_expected.not_to contain_exec('adding rule output-tcp dport 443 accept')
          is_expected.not_to contain_exec('adding rule output-tcp dport 53 accept')
          is_expected.not_to contain_exec('adding rule output-tcp dport 80 accept')
          is_expected.not_to contain_exec('adding rule output-udp dport 123 accept')
          is_expected.not_to contain_exec('adding rule output-udp dport 53 accept')
          is_expected.not_to contain_exec('adding rule output-tcp dport 20 accept')
        end
      }
    end
  end
end

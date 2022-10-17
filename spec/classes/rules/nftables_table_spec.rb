# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_table' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:pre_condition) do
        <<-EOF
        exec { 'dump nftables ruleset':
          command     => 'nft list ruleset > /etc/nftables/nftables.rules',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
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
              'tables_count' => 0,
              'tables_count_status' => false,
              'tables' => ['test1'],
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'nftables_default_table' => 'inet',
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_exec('create nft table inet')
            .with(
              'command' => 'nft create table inet filter',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test -z "$(nft list ruleset | grep -E \'^table inet\')"',
            )
            .that_notifies('Exec[dump nftables ruleset]')
        else
          is_expected.not_to contain_exec('create nft table inet')
        end
      }
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_flush_iptables' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_exec('flush iptables rules')
            .with(
              'command' => 'iptables -F',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test $(iptables -L | grep -c -e \'^ACCEPT\' -e \'^REJECT\' -e \'^DROP\') -gt 0',
            )

          is_expected.to contain_exec('flush ip6tables rules')
            .with(
              'command' => 'ip6tables -F',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test $(ip6tables -L | grep -c -e \'^ACCEPT\' -e \'^REJECT\' -e \'^DROP\') -gt 0',
            )
        end
      }
    end
  end
end

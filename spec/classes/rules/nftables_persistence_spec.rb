# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_persistence' do
  let(:pre_condition) do
    <<-EOF
    package { 'nftables':
      ensure => installed,
    }
    EOF
  end
  
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'cis_security_hardening' => {
            'services_enabled' => {
              'srv_nftables' => false,
            },
          },
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
          is_expected.to contain_file('/etc/sysconfig/nftables.conf')
            .with(
              'ensure' => 'file',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0644',
            )

          is_expected.to contain_file_line('add persistence file include')
            .with(
              'path'               => '/etc/sysconfig/nftables.conf',
              'line'               => 'include "/etc/nftables/nftables.rules"',
              'match'              => 'include "/etc/nftables/nftables.rules"',
              'append_on_no_match' => true,
            )
            .that_requires('Package[nftables]')

          is_expected.to contain_exec('dump nftables ruleset')
            .with(
              'command' => 'nft list ruleset > /etc/nftables/nftables.rules',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
            .that_requires('Package[nftables]')
        else
          is_expected.not_to contain_file('/etc/sysconfig/nftables.conf')
          is_expected.not_to contain_file_line('add persistence file include')
          is_expected.not_to contain_exec('dump nftables ruleset')
        end
      }
    end
  end
end

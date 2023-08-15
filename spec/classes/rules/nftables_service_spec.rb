# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nftables_service' do
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
          is_expected.to contain_service('nftables')
            .with(
              'ensure' => 'running',
              'enable' => true,
            )
            .that_requires('Package[nftables]')
        else
          is_expected.not_to contain_service('nftables')
        end
      }
    end
  end
end

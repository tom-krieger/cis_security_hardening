# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::firewalld_default_zone' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'cis_security_hardening' => {
            'firewalld' => {
              'default_zone' => 'private',
              'default_zone_status' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'default_zone' => 'public',
        }
      end

      it {
        is_expected.to compile

        if enforce
          is_expected.to contain_exec('set firewalld default zone')
            .with(
              'command' => 'firewall-cmd --set-default-zone=public',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )

        else
          is_expected.not_to contain_exec('set firewalld default zone')
        end
      }
    end
  end
end

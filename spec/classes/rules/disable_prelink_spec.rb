# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_prelink' do
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

          is_expected.to contain_package('prelink')
            .with(
              'ensure' => 'purged',
            )

          is_expected.to contain_exec('reset prelink')
            .with(
              'command' => 'prelink -ua',
              'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              'onlyif'  => 'test -f /sbin/prelink',
            )
            .that_comes_before('Package[prelink]')
        else
          is_expected.not_to contain_package('prelink')
        end
      }
    end
  end
end

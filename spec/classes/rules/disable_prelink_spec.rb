# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::disable_prelink' do
  test_on = {
    supported_os: [{
      'operatingsystem'        => 'RedHat',
      'operatingsystemrelease' => ['7', '8'],
    }]
  }

  on_supported_os(test_on).each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
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
end

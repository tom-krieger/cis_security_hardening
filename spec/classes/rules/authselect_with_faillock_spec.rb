# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::authselect_with_faillock' do
  enforce_options.each do |enforce|
    context 'on RedHat' do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'cis_security_hardening' => {
            'authselect' => {
              'current_options' => ['without-nullok'],
              'faillock' => 'none',
              'faillock_global' => 'with_faillock',
              'profile' => 'test',
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
          is_expected.to contain_exec('select authselect with-faillock')
            .with(
              'command' => 'authselect select custom/test with-sudo with-faillock without-nullok -f',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => ['test -d /etc/authselect/custom/test',
                            "test -z \"$(authselect current | grep 'with-faillock')\""],
              'returns' => [0, 1],
            )
        else
          is_expected.not_to contain_exec('select authselect with-faillock')
        end
      }
    end
  end
end

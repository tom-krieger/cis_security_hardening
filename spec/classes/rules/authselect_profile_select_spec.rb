# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::authselect_profile_select' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'cis_security_hardening' => {
            'authselect' => {
              'current_options' => ['with-faillock', 'without-nullok'],
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
          'custom_profile' => 'testprofile',
          'profile_options' => ['with-sudo', 'with-faillock', 'without-nullok'],
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('select authselect profile')
            .with(
              'command' => 'authselect select custom/testprofile with-sudo with-faillock without-nullok -f',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => ['test -d /etc/authselect/custom/testprofile', 'test -z "$(authselect current | grep \'custom/testprofile\')"'],
              'returns' => [0, 1],
            )
        else
          is_expected.not_to contain_exec('select authselect profile')
        end
      }
    end
  end
end

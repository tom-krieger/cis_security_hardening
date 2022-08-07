# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::authselect_profile' do
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
              'profile' => 'none',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'custom_profile' => 'testprofile',
          'base_profile' => 'sssd',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('set custom profile')
            .with(
              'command' => 'authselect create-profile testprofile -b sssd --symlink-meta',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'onlyif'  => 'test ! -d /etc/authselect/custom/testprofile',
            )
        else
          is_expected.not_to contain_exec('set custom profile')
        end
      }
    end
  end
end

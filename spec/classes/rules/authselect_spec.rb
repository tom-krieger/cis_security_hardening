# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::authselect' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              authselect: {
                available_features: [ 'with-sudo', 'with-altfiles', 'with-custom-aliases', 'with-custom-automount', 'with-custom-ethers', 'with-custom-group', 'with-custom-hosts',
                                      'with-custom-initgroups', 'with-custom-netgroup', 'with-custom-networks', 'with-custom-passwd', 'with-custom-protocols', 'with-custom-publickey',
                                      'with-custom-rpc', 'with-custom-services', 'with-custom-shadow', 'with-ecryptfs', 'with-faillock', 'with-mkhomedir', 'with-pamaccess',
                                      'with-silent-lastlog', 'without-nullok' ],
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'base_profile' => 'sssd',
            'custom_profile' => 'cis',
            'profile_options' => ['with-sudo', 'with-faillock', 'without-nullok', 'with-bad'],
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('create custom profile')
              .with(
                'command' => 'authselect create-profile cis -b sssd --symlink-meta',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test ! -d /etc/authselect/custom/cis',
              )

            is_expected.to contain_exec('select authselect profile')
              .with(
                'command' => 'authselect select custom/cis -f',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => ['test -d /etc/authselect/custom/cis', "test -z \"$(authselect current | grep 'custom/cis')\""],
                'returns' => [0, 1],
              )
              .that_requires('Exec[create custom profile]')

            is_expected.to contain_exec('enable feature with-sudo')
              .with(
                'command' => 'authselect enable-feature with-sudo',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => ['test -d /etc/authselect/custom/cis', "test -z \"$(authselect current | grep 'with-sudo')\""],
              )
              .that_requires('Exec[select authselect profile]')

            is_expected.to contain_exec('enable feature with-faillock')
              .with(
                'command' => 'authselect enable-feature with-faillock',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => ['test -d /etc/authselect/custom/cis', "test -z \"$(authselect current | grep 'with-faillock')\""],
              )
              .that_requires('Exec[select authselect profile]')

            is_expected.to contain_exec('enable feature without-nullok')
              .with(
                'command' => 'authselect enable-feature without-nullok',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => ['test -d /etc/authselect/custom/cis', "test -z \"$(authselect current | grep 'without-nullok')\""],
              )
              .that_requires('Exec[select authselect profile]')

            is_expected.to contain_echo('unavailable feature with-bad')
              .with(
                'message'  => 'authselect: unavailable feature with-bad',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          else
            is_expected.not_to contain_exec('create custom profile')
            is_expected.not_to contain_exec('select authselect profile')
            is_expected.not_to contain_exec('enable feature with-sudo')
            is_expected.not_to contain_exec('enable feature with-faillock')
            is_expected.not_to contain_exec('enable feature with-nullok')
            is_expected.not_to contain_echo('unavailable feature with-bad')
          end
        }
      end
    end
  end
end

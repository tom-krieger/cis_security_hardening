# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::home_usrquota' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          {
            mountpoints: {
              '/home': {
                available: '1.85 GiB',
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
            is_expected.to contain_cis_security_hardening__set_mount_options('/home-usrquota')
              .with(
                'mountpoint'   => '/home',
                'mountoptions' => 'usrquota',
              )
            is_expected.to contain_cis_security_hardening__set_mount_options('/home-usrquota-quota')
              .with(
                'mountpoint'   => '/home',
                'mountoptions' => 'quota',
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/home-usrquota')
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/home-usrquota-quota')
          end
        }
      end
    end
  end
end

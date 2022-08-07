# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::apparmor_profiles' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'apparmor' => {
                'bootloader' => false,
                'profiles' => 17,
                'profiles_enforced' => 15,
                'profiles_complain' => 2,
              },
              'access_control' => 'none',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_exec('apparmor enforce')
              .with(
                'command' => 'aa-enforce /etc/apparmor.d/*',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )
          else
            is_expected.not_to contain_exec('apparmor enforce')
          end
        end
      end
    end
  end
end

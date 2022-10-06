# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::home_noexec' do
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
            is_expected.to contain_cis_security_hardening__set_mount_options('/home-noexec')
              .with(
                'mountpoint'   => '/home',
                'mountoptions' => 'noexec',
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/home-noexec')
          end
        }
      end
    end
  end
end

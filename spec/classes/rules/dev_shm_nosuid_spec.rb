# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dev_shm_nosuid' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          class { 'cis_security_hardening::rules::dev_shm':
            enforce => false,
            size    => 0,
          }
          EOF
        end
        let(:facts) do
          {
            mountpoints: {
              '/dev/shm': {
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
            is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm-nosuid')
              .with(
                'mountpoint'   => '/dev/shm',
                'mountoptions' => 'nosuid',
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm-nosuid')
          end
        }
      end
    end
  end
end

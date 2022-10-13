# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::dev_shm' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:params) do
          {
            'enforce' => enforce,
            'size'    => 2,
          }
        end

        let(:facts) { os_facts }

        it {
          is_expected.to compile
          if enforce
            # is_expected.to contain_fstab('/dev/shm entry')
            #   .with(
            #     'source' => 'tmpfs',
            #     'dest'   => '/dev/shm',
            #     'type'   => 'tmpfs',
            #     'opts'   => 'defaults,size=2G,nodev,nosuid,noexec,seclabel',
            #     'dump'   => 0,
            #     'passno' => 0,
            #   )

            is_expected.to contain_cis_security_hardening__set_mount_options('/dev/shm')
              .with(
                'mountpoint'   => '/dev/shm',
                'mountoptions' => 'size=2G',
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm')
          end
        }
      end
    end
  end
end

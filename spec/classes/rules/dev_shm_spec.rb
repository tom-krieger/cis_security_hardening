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
            is_expected.to contain_file_line('add /dev/shm to fstab')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/fstab',
                'match'              => "^tmpfs\\s* /dev/shm",
                'line'               => 'tmpfs   /dev/shm        tmpfs   defaults,size=2G,nodev,nosuid,noexec,seclabel   0 0',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/dev/shm')
            is_expected.not_to contain_file_line('add /dev/shm to fstab')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nfs_noexec' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              nfs_file_systems: {
                '/export/store' => {
                  'device' => '10.10.10.10:/volume1/store',
                  'mountoptions' => 'defaults,vers=3'
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_cis_security_hardening__set_mount_options('/export/store-noexec')
              .with(
                'mountpoint'   => '/export/store',
                'mountoptions' => 'noexec',
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/export/store-noexec')
          end
        }
      end
    end
  end
end

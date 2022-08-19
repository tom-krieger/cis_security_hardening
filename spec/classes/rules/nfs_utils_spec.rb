# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::nfs_utils' do
  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context 'on RedHat' do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:operatingsystem].casecmp('sles').zero?
              is_expected.to contain_package('nfs-utils')
                .with(
                  'ensure' => 'absent',
                )

              is_expected.to contain_package('nfs-kernel-server')
                .with(
                  'ensure' => 'absent',
                )
            elsif os_facts[:operatingsystem].casecmp('rocky').zero?
              is_expected.to contain_package('nfs-utils')
                .with(
                  'ensure' => 'absent',
                )
            else
              is_expected.to contain_service('nfs-server')
                .with(
                  'ensure' => 'stopped',
                  'enable' => false,
                )
              is_expected.to contain_package('nfs-utils')
                .with(
                  'ensure' => 'absent',
                )
            end
          else
            is_expected.not_to contain_service('nfs-server')
            is_expected.not_to contain_package('nfs-utils')
            is_expected.not_to contain_package('nfs-kernel-server')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::var_log_audit_nosuid' do
  on_supported_os.each do |os, _os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          {
            mountpoints: {
              '/var/log/audit': {
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
            is_expected.to contain_cis_security_hardening__set_mount_options('/var/log/audit-nosuid')
              .with(
                'mountpoint'   => '/var/log/audit',
                'mountoptions' => 'nosuid',
              )
          else
            is_expected.not_to contain_cis_security_hardening__set_mount_options('/var/log/audit-nosuid')
          end
        }
      end
    end
  end
end

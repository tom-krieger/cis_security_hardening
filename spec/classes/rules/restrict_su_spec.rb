# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::restrict_su' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'wheel_users' => ['root'],
            'sudo_group' => 'wheel'
          }
        end

        it {
          is_expected.to compile
          if enforce
            if os_facts[:os]['family'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] >= '9'
              is_expected.to contain_pam('pam-su-restrict')
                .with(
                  'ensure'    => 'present',
                  'service'   => 'su',
                  'type'      => 'auth',
                  'control'   => 'required',
                  'module'    => 'pam_wheel.so',
                  'arguments' => ['use_uid'],
                )
            else
              is_expected.to contain_pam('pam-su-restrict')
                .with(
                  'ensure'    => 'present',
                  'service'   => 'su',
                  'type'      => 'auth',
                  'control'   => 'required',
                  'module'    => 'pam_wheel.so',
                  'arguments' => ['use_uid', 'group=wheel'],
                )
            end
            is_expected.to contain_exec('root_wheel')
              .with(
                'command' => 'usermod -G wheel root',
                'unless'  => 'grep wheel /etc/group | grep root',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )

            is_expected.to contain_group('wheel')
              .with(
                'ensure' => 'present',
              )

          else
            is_expected.not_to contain_pam('pam-su-restrict')
            is_expected.not_to contain_exec('root_wheel')
            is_expected.not_to contain_group('wheel')
          end
        }
      end
    end
  end
end

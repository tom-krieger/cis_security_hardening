# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::gdm_autologin' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            cis_security_hardening: {
              xdcmp: true,
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
            filename = if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero? ||
                          os_facts[:operatingsystem].casecmp('centos').zero? || os_facts[:operatingsystem].casecmp('redhat').zero?
                         '/etc/gdm/custom.conf'
                       else
                         '/etc/gdm3/custom.conf'
                       end

            is_expected.to contain_ini_setting('gdm-autologin')
              .with(
                'ensure'  => 'present',
                'path'    => filename,
                'section' => 'daemon',
                'setting' => 'AutomaticLoginEnable',
                'value'   => 'false',
              )

            is_expected.to contain_ini_setting('gdm-unrestricted')
              .with(
                'ensure'  => 'present',
                'path'    => filename,
                'section' => 'daemon',
                'setting' => 'TimedLoginEnable',
                'value'   => 'false',
              )

          else
            is_expected.not_to contain_ini_setting('gdm-autologin')
            is_expected.not_to contain_ini_setting('gdm-unrestricted')
          end
        }
      end
    end
  end
end

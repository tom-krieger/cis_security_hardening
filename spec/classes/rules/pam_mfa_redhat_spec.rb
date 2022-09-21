# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_mfa_redhat' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_package('dconf')
              .with(
                'ensure' => 'present',
              )

            is_expected.to contain_file_line('authconfig-config-smartcard')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/sysconfig/authconfig',
                'match'              => '^USESMARTCARD=',
                'line'               => 'USESMARTCARD=yes',
                'append_on_no_match' => true,
              )

            is_expected.to contain_file_line('authconfig-config-force-smartcard')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/sysconfig/authconfig',
                'match'              => '^FORCESMARTCARD=',
                'line'               => 'FORCESMARTCARD=yes',
                'append_on_no_match' => true,
              )

            is_expected.to contain_pam('pkcs11-system-auth')
              .with(
                'ensure'           => 'present',
                'service'          => 'system-auth',
                'type'             => 'auth',
                'control'          => '[success=done ignore=ignore default=die]',
                'control_is_param' => true,
                'module'           => 'pam_pkcs11.so',
                'arguments'        => ['nodebug', 'wait_for_card'],
                'position'         => 'before *[type="auth" and module="pam_unix.so"]',
              )

            is_expected.to contain_pam('pkcs11-smartcard-auth-auth')
              .with(
                'ensure'           => 'present',
                'service'          => 'smartcard-auth',
                'type'             => 'auth',
                'control'          => '[success=done ignore=ignore default=die]',
                'control_is_param' => true,
                'module'           => 'pam_pkcs11.so',
                'arguments'        => ['nodebug', 'wait_for_card'],
                'position'         => 'after *[type="auth" and module="pam_faillock.so"]',
              )

            is_expected.to contain_pam('pkcs11-smartcard-auth-password')
              .with(
                'ensure'  => 'present',
                'service' => 'smartcard-auth',
                'type'    => 'password',
                'control' => 'required',
                'module'  => 'pam_pkcs11.so',
              )

            is_expected.to contain_file_line('screensaver-lock')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/pam_pkcs11/pkcs11_eventmgr.conf',
                'match'              => "#\s*action = \"/usr/sbin/gdm-safe-restart\", \"/etc/pkcs11/lockhelper.sh -deactivate\";",
                'line'               => "\t\taction = \"/usr/sbin/gdm-safe-restart\", \"/etc/pkcs11/lockhelper.sh -deactivate\", \"/usr/X11R6/bin/xscreensaveer-command -lock\";",
                'append_on_no_match' => false,
              )
              .that_requires('Package[dconf]')
          else
            is_expected.not_to contain_package('dconf')
            is_expected.not_to contain_file_line('authconfig-config-smartcard')
            is_expected.not_to contain_file_line('authconfig-config-force-smartcard')
            is_expected.not_to contain_pam('pkcs11-system-auth')
            is_expected.not_to contain_pam('pkcs11-smartcard-auth-auth')
            is_expected.not_to contain_pam('pkcs11-smartcard-auth-password')
            is_expected.not_to contain_file_line('screensaver-lock')
          end
        }
      end
    end
  end
end

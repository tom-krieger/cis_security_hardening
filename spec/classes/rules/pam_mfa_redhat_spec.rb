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
            
            is_expected.to contain_exec('enable smartcard')
              .with(
                'command' => 'authconfig --enablesmartcard --smartcardaction=0 --update',
                'path'    => ['bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(grep -E \"auth\s*\[success=done ignore=ignore default=die\] pam_pkcs11.so\" /etc/pam.d/smartcard-auth)"',
              )
              .that_requires('Package[dconf]')
            
            is_expected.to contain_exec('enable required smartcard')
              .with(
                'command' => 'authconfig --enablerequiresmartcard --update',
                'path'    => ['bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => 'test -z "$(grep -E \"auth\s*\[success=done ignore=ignore default=die\] pam_pkcs11.so\" /etc/pam.d/smartcard-auth)"',
              )
              .that_requires(['Package[dconf]','Exec[enable smartcard]'])

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
            is_expected.not_to contain_exec('enable smartcard')
            is_expected.not_to contain_exec('enable required smartcard')
            is_expected.not_to contain_file_line('screensaver-lock')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_old_passwords' do
  let(:pre_condition) do
    <<-EOF
    exec { 'authselect-apply-changes':
      command     => 'authselect apply-changes',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            cis_security_hardening: {
              authselect: {
                profile: 'testprofile',
              },
              pam: {
                pwquality: {
                  status: false,
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'oldpasswords' => 5,
            'enforce_for_root' => true,
          }
        end

        it { is_expected.to compile }
        it do
          if enforce

            if os_facts[:os]['family'].casecmp('redhat').zero?

              if os_facts[:os]['release']['major'] == '7'
                is_expected.to contain_pam('pam-system-auth-sufficient')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'password',
                    'control'   => 'sufficient',
                    'module'    => 'pam_unix.so',
                    'arguments' => ['sha512', 'remember=5', 'shadow', 'try_first_pass', 'use_authtok'],
                    'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
                  )

                is_expected.to contain_pam('pam-password-auth-sufficient')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'password-auth',
                    'type'      => 'password',
                    'control'   => 'sufficient',
                    'module'    => 'pam_unix.so',
                    'arguments' => ['sha512', 'remember=5', 'shadow', 'try_first_pass', 'use_authtok'],
                    'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
                  )

                is_expected.not_to contain_exec('update authselect config for old passwords')
              else
                is_expected.not_to contain_pam('pam-system-auth-sufficient')
                is_expected.not_to contain_pam('pam-password-auth-sufficient')

                # rubocop:disable Layout/LineLength
                is_expected.to contain_exec('update authselect config for old passwords')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)(remember=\\S+\\s*)(.*)$/\\1\\4 remember=5 \\6/' /etc/authselect/custom/testprofile/system-auth || sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)$/\\1\\4 remember=5/' /etc/authselect/custom/testprofile/system-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z '\$(grep -E '^\\s*password\\s+(sufficient\\s+pam_unix|requi(red|site)\\s+pam_pwhistory).so\\s+ ([^#]+\\s+)*remember=\\S+\s*.*\$' /etc/authselect/custom/testprofile/system-auth)'",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')
                # rubocop:enable Layout/LineLength

                is_expected.to contain_pam('pam-_unix_sufficient')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'password',
                    'control'   => 'sufficient',
                    'module'    => 'pam_unix.so',
                    'arguments' => ['sha512', 'remember=5', 'shadow', 'try_first_pass', 'use_authtok'],
                    'target'    => '/etc/authselect/custom/testprofile/system-auth',
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_file('/etc/security/pwhistory.conf')
                  .with(
                    'ensure' => 'file',
                    'owner'  => 'root',
                    'group'  => 'root',
                    'mode'   => '0644',
                  )

                is_expected.to contain_file_line('pwhistory remember')
                  .with(
                    'path'               => '/etc/security/pwhistory.conf',
                    'match'              => '^remember\\s*=',
                    'append_on_no_match' => true,
                    'line'               => 'remember=5',
                  )
              end

            elsif os_facts[:os]['family'].casecmp('debian').zero? || os_facts[:os]['family'].casecmp('suse').zero?
              is_expected.not_to contain_pam('pam-system-auth-sufficient')
              is_expected.not_to contain_pam('pam-password-auth-sufficient')
              is_expected.not_to contain_exec('update authselect config for old passwords')

              if os_facts[:os]['name'].casecmp('debian').zero? && os_facts[:os]['release']['major'] > '10'
                is_expected.to contain_pam('pam-common-password-requisite-pwhistory')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'common-password',
                    'type'      => 'password',
                    'control'   => 'required',
                    'module'    => 'pam_pwhistory.so',
                    'position'  => 'before *[type="password" and module="pam_unix.so"]',
                    'arguments' => ['use_authok', 'remember=5'],
                  )
              elsif os_facts[:os]['name'].casecmp('ubuntu').zero? && os_facts[:os]['release']['major'] >= '20'
                is_expected.to contain_pam('ubuntu-remember-old-pw')
                  .with(
                    'ensure'           => 'present',
                    'service'          => 'common-password',
                    'type'             => 'password',
                    'control'          => '[success=1 default=ignore]',
                    'control_is_param' => true,
                    'module'           => 'pam_unix.so',
                    'arguments'        => ['obscure', 'use_authok', 'try_first_pass', 'yescrypt', 'remember=5'],
                    'position'         => 'before *[type="password" and module="pam_deny.so"]',
                  )

              else
                is_expected.to contain_pam('pam-common-password-requisite-pwhistory')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'common-password',
                    'type'      => 'password',
                    'control'   => 'required',
                    'module'    => 'pam_pwhistory.so',
                    'arguments' => ['remember=5'],
                  )
              end
            end

          else
            is_expected.not_to contain_pam('pam-system-auth-sufficient')
            is_expected.not_to contain_pam('pam-password-auth-sufficient')
            is_expected.not_to contain_exec('update authselect config for old passwords')
            is_expected.not_to contain_file('/etc/security/pwhistory.conf')
            is_expected.not_to contain_file_line('pwhistory remener')
          end
        end
      end
    end
  end
end

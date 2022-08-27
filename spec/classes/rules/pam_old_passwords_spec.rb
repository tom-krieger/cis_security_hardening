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
          os_facts.merge!(
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
          }
        end

        it { is_expected.to compile }
        it do
          if enforce

            if os_facts[:osfamily].casecmp('redhat').zero?

              if os_facts[:operatingsystemmajrelease] == '7'
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
              end

              if os_facts[:operatingsystem].casecmp('rocky').zero? || os_facts[:operatingsystem].casecmp('almalinux').zero?
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
              end

            elsif os_facts[:osfamily].casecmp('debian').zero? || os_facts[:osfamily].casecmp('suse').zero?
              is_expected.not_to contain_pam('pam-system-auth-sufficient')
              is_expected.not_to contain_pam('pam-password-auth-sufficient')
              is_expected.not_to contain_exec('update authselect config for old passwords')
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

          else
            is_expected.not_to contain_pam('pam-system-auth-sufficient')
            is_expected.not_to contain_pam('pam-password-auth-sufficient')
            is_expected.not_to contain_exec('update authselect config for old passwords')
          end
        end
      end
    end
  end
end

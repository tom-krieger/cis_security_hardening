# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_lockout' do
  let(:pre_condition) do
    <<-EOF
    exec { 'authselect-apply-changes':
      command     => 'authselect apply-changes',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }

    exec { 'authconfig-apply-changes':
      command     => 'authconfig --updateall',
      path        => ['/sbin','/usr/sbin'],
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
            'lockouttime' => 900,
            'attempts' => 3,
            'lockout_root' => true,
            'lock_dir' => '/tmp/faillock',
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:osfamily].casecmp('redhat').zero?

              if os_facts[:operatingsystemmajrelease] == '7'
                is_expected.to contain_pam('pam-auth-faillock-required-2-system-auth')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'auth',
                    'control'   => '[default=die]',
                    'control_is_param' => true,
                    'module'    => 'pam_faillock.so',
                    'arguments' => ['authfail', 'audit', 'deny=3', 'unlock_time=900'],
                    'position'  => 'after *[type="auth" and module="pam_unix.so"]',
                  )

                is_expected.to contain_pam('pam-auth-faillock-required-2-password-auth')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'password-auth',
                    'type'      => 'auth',
                    'control'   => '[default=die]',
                    'control_is_param' => true,
                    'module'    => 'pam_faillock.so',
                    'arguments' => ['authfail', 'audit', 'deny=3', 'unlock_time=900'],
                    'position'  => 'after *[type="auth" and module="pam_unix.so"]',
                  )

                is_expected.to contain_pam('account-faillock-system-auth')
                  .with(
                    'ensure'  => 'present',
                    'service' => 'system-auth',
                    'type'    => 'account',
                    'control' => 'required',
                    'module'  => 'pam_faillock.so',
                  )

                is_expected.to contain_pam('account-faillock-password-auth')
                  .with(
                    'ensure'  => 'present',
                    'service' => 'password-auth',
                    'type'    => 'account',
                    'control' => 'required',
                    'module'  => 'pam_faillock.so',
                  )

                is_expected.to contain_pam("disable-nullok-system-auth")
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'auth',
                    'module'    => 'pam_unix.so',
                    'arguments' => ['try_first_pass'],
                  )

                is_expected.to contain_pam("disable-nullok-password-auth")
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'password-auth',
                    'type'      => 'auth',
                    'module'    => 'pam_unix.so',
                    'arguments' => ['try_first_pass'],
                  )

                is_expected.to contain_exec('configure faillock')
                  .with(
                    'command' => 'authconfig --faillockargs="preauth silent audit even_deny_root deny=3 unlock_time=900" --enablefaillock --updateall',
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E \"auth\\s+required\\s+pam_faillock.so.*deny=3\\s+unlock_time=900\" /etc/pam.d/system-auth)\"",
                  )
                is_expected.not_to contain_file__line('update pam lockout system-auth')
                is_expected.not_to contain_file__line('update pam lockout password-auth')
              else
                is_expected.not_to contain_pam('pam-auth-faillock-required')
                is_expected.not_to contain_pam('pam-auth-faillock-required-2')
                is_expected.not_to contain_pam('account-faillock-system-auth')
                is_expected.not_to contain_pam('account-faillock-password-auth')
                is_expected.not_to contain_pam("disable-nullok-system-auth")
                is_expected.not_to contain_pam("disable-nullok-password-auth")

                is_expected.to contain_file_line('update pam lockout system-auth')
                  .with(
                    'path'   => '/etc/authselect/custom/testprofile/system-auth',
                    'line'   => 'auth         required                                     pam_faillock.so preauth silent deny=3 unlock_time=900  {include if "with-faillock"}',
                    'match'  => '^auth\s+required\s+pam_faillock.so\s+preauth\s+silent',
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_file_line('update pam lockout password-auth')
                  .with(
                    'path'   => '/etc/authselect/custom/testprofile/password-auth',
                    'line'   => 'auth         required                                     pam_faillock.so preauth silent deny=3 unlock_time=900  {include if "with-faillock"}',
                    'match'  => '^auth\s+required\s+pam_faillock.so\s+preauth\s+silent',
                  )
                  .that_notifies('Exec[authselect-apply-changes]')
              end

              if os_facts[:operatingsystem].casecmp('redhat').zero? && os_facts[:operatingsystemmajrelease] >= '8'
                is_expected.to contain_file_line('faillock_fail_interval')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^fail_interval =',
                    'line'               => 'fail_interval = 900',
                    'append_on_no_match' => true,
                  )

                is_expected.to contain_file_line('faillock_deny')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^deny =',
                    'line'               => 'deny = 3',
                    'append_on_no_match' => true,
                  )

                is_expected.to contain_file_line('faillock_fail_unlock_time')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^unlock_time =',
                    'line'               => 'unlock_time = 900',
                    'append_on_no_match' => true,
                  )

                is_expected.to contain_file_line('faillock_dir')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^dir =',
                    'line'               => 'dir = /tmp/faillock',
                    'append_on_no_match' => true,
                  )

                is_expected.to contain_file_line('faillock_silent')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^silent',
                    'line'               => 'silent',
                    'append_on_no_match' => true,
                  )

                is_expected.to contain_file_line('faillock_audit')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^audit',
                    'line'               => 'audit',
                    'append_on_no_match' => true,
                  )

                is_expected.to contain_file_line('faillock_even_deny_root')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/security/faillock.conf',
                    'match'              => '^even_deny_root',
                    'line'               => 'even_deny_root',
                    'append_on_no_match' => true,
                  )
              end

            elsif os_facts[:osfamily].casecmp('debian').zero?

              is_expected.not_to contain_file__line('update pam lockout system-auth')
              is_expected.not_to contain_file__line('update pam lockout password-auth')
              is_expected.not_to contain_exec('configure faillock')
              is_expected.not_to contain_file_line('faillock_fail_interval')
              is_expected.not_to contain_file_line('faillock_deny')
              is_expected.not_to contain_file_line('faillock_unlock_time')
              is_expected.not_to contain_file_line('faillock_dir')
              is_expected.not_to contain_file_line('faillock_silent')
              is_expected.not_to contain_file_line('faillock_even_deny_root')

              is_expected.to contain_pam('pam-common-auth-require-tally2')
                .with(
                  'ensure'    => 'present',
                  'service'   => 'common-auth',
                  'type'      => 'auth',
                  'control'   => 'required',
                  'module'    => 'pam_tally2.so',
                  'arguments' => ['onerr=fail', 'audit', 'silent', 'deny=3', 'unlock_time=900'],
                )

              is_expected.to contain_pam('pam-common-account-requisite-deny')
                .with(
                  'ensure'  => 'present',
                  'service' => 'common-account',
                  'type'    => 'account',
                  'control' => 'requisite',
                  'module'  => 'pam_deny.so',
                )

              is_expected.to contain_pam('pam-common-account-require-tally2')
                .with(
                  'ensure'  => 'present',
                  'service' => 'common-account',
                  'type'    => 'account',
                  'control' => 'required',
                  'module'  => 'pam_tally2.so',
                )
            elsif os_facts[:osfamily].casecmp('suse').zero?

              is_expected.not_to contain_file_line('faillock_fail_interval')
              is_expected.not_to contain_file_line('faillock_deny')
              is_expected.not_to contain_file_line('faillock_unlock_time')
              is_expected.not_to contain_file_line('faillock_dir')
              is_expected.not_to contain_file_line('faillock_silent')
              is_expected.not_to contain_file_line('faillock_even_deny_root')

              is_expected.to contain_pam('pam-auth-required')
                .with(
                  'ensure'    => 'present',
                  'service'   => 'login',
                  'type'      => 'auth',
                  'control'   => 'required',
                  'module'    => 'pam_tally2.so',
                  'arguments' => ['deny=3', 'onerr=fail', 'unlock_time=900'],
                  'position'  => 'after *[type="auth" and module="pam_env.so"]',
                )
              is_expected.to contain_pam('pam-account-required')
                .with(
                  'ensure'  => 'present',
                  'service' => 'common-account',
                  'type'    => 'account',
                  'control' => 'required',
                  'module'  => 'pam_tally2.so',
                )
            end

          else
            is_expected.not_to contain_pam('pam-auth-faillock-required')
            is_expected.not_to contain_pam('pam-auth-faillock-require-2')
            is_expected.not_to contain_pam('account-faillock-system-auth')
            is_expected.not_to contain_pam('account-faillock-password-auth')
            is_expected.not_to contain_pam('pam-common-auth-require-tally2')
            is_expected.not_to contain_pam('pam-common-account-requisite-deny')
            is_expected.not_to contain_pam('pam-common-account-require-tally2')
            is_expected.not_to contain_exec('configure faillock')
            is_expected.not_to contain_pam('pam_unix system-auth')
            is_expected.not_to contain_pam('pam_faillock preauth system-auth')
            is_expected.not_to contain_pam('pam_faillock authfail system-auth')
            is_expected.not_to contain_pam('pam_faillock authsucc system-auth')
            is_expected.not_to contain_pam('pam_unix password-auth')
            is_expected.not_to contain_pam('pam_faillock preauth password-auth')
            is_expected.not_to contain_pam('pam_faillock authfail password-auth')
            is_expected.not_to contain_pam('pam_faillock authsucc password-auth')
            is_expected.not_to contain_file__line('update pam lockout system-auth')
            is_expected.not_to contain_file__line('update pam lockout password-auth')
            is_expected.not_to contain_file_line('faillock_fail_interval')
            is_expected.not_to contain_file_line('faillock_deny')
            is_expected.not_to contain_file_line('faillock_unlock_time')
            is_expected.not_to contain_file_line('faillock_dir')
            is_expected.not_to contain_file_line('faillock_silent')
            is_expected.not_to contain_file_line('faillock_even_deny_root')
            is_expected.not_to contain_pam("disable-nullok-system-auth")
            is_expected.not_to contain_pam("disable-nullok-password-auth")
          end
        }
      end
    end
  end
end

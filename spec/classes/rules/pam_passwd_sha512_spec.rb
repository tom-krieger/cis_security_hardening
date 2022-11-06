# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_passwd_sha512' do
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

  on_supported_os.each do |_os, os_facts|
    enforce_options.each do |enforce|
      context "on RedHat 7 with enforce #{enforce}" do
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
          }
        end

        it {
          is_expected.to compile
          if enforce

            if os_facts[:os]['family'].casecmp('redhat').zero?

              if os_facts[:os]['release']['major'] == '7'
                is_expected.not_to contain_exec('update authselect config for sha512 system-auth')
                is_expected.not_to contain_exec('update authselect config for sha512 password-auth')

                is_expected.to contain_file_line('password algorithm sha512')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/sysconfig/authconfig',
                    'match'              => '^PASSWDALGORITHM=',
                    'line'               => 'PASSWDALGORITHM=sha512',
                    'append_on_no_match' => true,
                  )
                  .that_notifies('Exec[authconfig-passalgo-sha512]')

                is_expected.to contain_exec('authconfig-passalgo-sha512')
                  .with(
                    'command'     => 'authconfig --passalgo=sha512 --updateall',
                    'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'refreshonly' => true,
                  )

              else
                is_expected.not_to contain_file_line('password algorithm sha512')
                is_expected.not_to contain_pam('sha512-system-auth')
                is_expected.not_to contain_pam('sha512-password-auth')
                is_expected.not_to contain_exec('authconfig-passalgo-sha512')

                is_expected.to contain_exec('update authselect config for sha512 system-auth')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' /etc/authselect/custom/testprofile/system-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*\$' /etc/authselect/custom/testprofile/system-auth)\"",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_exec('update authselect config for sha512 password-auth')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' /etc/authselect/custom/testprofile/password-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*\$' /etc/authselect/custom/testprofile/password-auth)\"",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')
              end

            elsif os_facts[:os]['family'].casecmp('debian').zero?
              is_expected.not_to contain_exec('update authselect config for sha512 system-auth')
              is_expected.not_to contain_exec('update authselect config for sha512 password-auth')
              is_expected.not_to contain_exec('switch sha512 on')

              is_expected.to contain_pam('pam-common-password-unix')
                .with(
                  'ensure'           => 'present',
                  'service'          => 'common-password',
                  'type'             => 'password',
                  'control'          => '[success=1 default=ignore]',
                  'control_is_param' => true,
                  'module'           => 'pam_unix.so',
                  'arguments'        => ['sha512'],
                )

            end

          else
            is_expected.not_to contain_exec('update authselect config for sha512 system-auth')
            is_expected.not_to contain_exec('update authselect config for sha512 password-auth')
            is_expected.not_to contain_exec('switch sha512 on')
            is_expected.not_to contain_pam('pam-common-password-unix')
            is_expected.not_to contain_exec('authconfig-passalgo-sha512')
          end
        }
      end

      context "on RedHat 8 with enforce #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          exec { 'authselect-apply-changes':
            command     => 'authselect apply-changes',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          {
            osfamily: 'RedHat',
            operatingsystem: 'CentOS',
            architecture: 'x86_64',
            operatingsystemmajrelease: '8',
            cis_security_hardening: {
              authselect: {
                profile: 'testprofile',
              },
              pam: {
                sha512: {
                  status: false,
                },
              },
            },
          }
        end
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it { is_expected.to compile }
        it {
          if enforce
            is_expected.to contain_exec('update authselect config for sha512 system-auth')
              .with(
                'command' => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' /etc/authselect/custom/testprofile/system-auth",
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*\$' /etc/authselect/custom/testprofile/system-auth)\"",
              )
              .that_notifies('Exec[authselect-apply-changes]')

            is_expected.to contain_exec('update authselect config for sha512 password-auth')
              .with(
                'command' => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' /etc/authselect/custom/testprofile/password-auth",
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*\$' /etc/authselect/custom/testprofile/password-auth)\"",
              )
              .that_notifies('Exec[authselect-apply-changes]')
          else
            is_expected.not_to contain_exec('update authselect config for sha512 system-auth')
            is_expected.not_to contain_exec('update authselect config for sha512 password-auth')
            is_expected.not_to contain_exec('switch sha512 on')
          end
        }
      end
    end
  end
end

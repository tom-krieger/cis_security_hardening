# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_pw_requirements' do
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
            'minlen' => 14,
            'dcredit' => -1,
            'ucredit' => -1,
            'lcredit' => -1,
            'ocredit' => -1,
            'minclass' => 4,
            'retry' => 3,
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:osfamily].casecmp('redhat').zero?

              is_expected.not_to contain_package('libpam-pwquality')

              is_expected.to contain_file_line('pam minlen')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'minlen = 14',
                  'match'  => '^#?minlen',
                )

              if os_facts[:operatingsystemmajrelease] == '7'
                is_expected.not_to contain_file_line('pam minclass')

                is_expected.to contain_file_line('pam dcredit')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'dcredit = -1',
                    'match'  => '^#?dcredit',
                  )

                is_expected.to contain_file_line('pam ucredit')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'ucredit = -1',
                    'match'  => '^#?ucredit',
                  )

                is_expected.to contain_file_line('pam ocredit')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'ocredit = -1',
                    'match'  => '^#?ocredit',
                  )

                is_expected.to contain_file_line('pam lcredit')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'lcredit = -1',
                    'match'  => '^#?lcredit',
                  )

                is_expected.to contain_pam('pam-system-auth-requisite')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'password',
                    'control'   => 'requisite',
                    'module'    => 'pam_pwquality.so',
                    'arguments' => ['try_first_pass', 'retry=3'],
                  )

                is_expected.to contain_pam('pam-password-auth-requisite')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'password-auth',
                    'type'      => 'password',
                    'control'   => 'requisite',
                    'module'    => 'pam_pwquality.so',
                    'arguments' => ['try_first_pass', 'retry=3'],
                  )
              else
                is_expected.to contain_file_line('pam minclass')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'minclass = 4',
                    'match'  => '^#?minclass',
                  )

                is_expected.to contain_exec('update authselect config enforce for root system-auth')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+requisite\\s+pam_pwquality.so\\s+)(.*)$/\\1\\2 enforce-for-root/' /etc/authselect/custom/testprofile/system-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*enforce-for-root\\s*.*\$' /etc/authselect/custom/testprofile/system-auth)\"",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_exec('update authselect config retry system-auth')
                  .with(
                    'command' => "sed -ri '/pwquality/s/retry=\\S+/retry=3/' /etc/authselect/custom/testprofile/system-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*\\s+retry=\\S+\\s*.*\$' /etc/authselect/custom/testprofile/system-auth)\"",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_exec('update authselect config retry (2) system-auth')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+requisite\\s+pam_pwquality.so\\s+)(.*)$/\\1\\2 retry=3/' /etc/authselect/custom/testprofile/system-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*\\s+retry=\\S+\\s*.*\$' /etc/authselect/custom/testprofile/system-auth)\"",
                  )

                is_expected.to contain_exec('update authselect config enforce for root password-auth')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+requisite\\s+pam_pwquality.so\\s+)(.*)$/\\1\\2 enforce-for-root/' /etc/authselect/custom/testprofile/password-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*enforce-for-root\\s*.*\$' /etc/authselect/custom/testprofile/password-auth)\"",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_exec('update authselect config retry password-auth')
                  .with(
                    'command' => "sed -ri '/pwquality/s/retry=\\S+/retry=3/' /etc/authselect/custom/testprofile/password-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*\\s+retry=\\S+\\s*.*\$' /etc/authselect/custom/testprofile/password-auth)\"",
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_exec('update authselect config retry (2) password-auth')
                  .with(
                    'command' => "sed -ri 's/^\\s*(password\\s+requisite\\s+pam_pwquality.so\\s+)(.*)$/\\1\\2 retry=3/' /etc/authselect/custom/testprofile/password-auth",
                    'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                    'onlyif'  => "test -z \"\$(grep -E '^\\s*password\\s+requisite\\s+pam_pwquality.so\\s+.*\\s+retry=\\S+\\s*.*\$' /etc/authselect/custom/testprofile/password-auth)\"",
                  )
              end

            elsif os_facts[:osfamily].casecmp('debian').zero?

              is_expected.to contain_file_line('pam dcredit')
                .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'dcredit = -1',
                    'match'  => '^#?dcredit',
                  )

              is_expected.to contain_file_line('pam ucredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'ucredit = -1',
                  'match'  => '^#?ucredit',
                )

              is_expected.to contain_file_line('pam ocredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'ocredit = -1',
                  'match'  => '^#?ocredit',
                )

              is_expected.to contain_file_line('pam lcredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'lcredit = -1',
                  'match'  => '^#?lcredit',
                )

              is_expected.to contain_file_line('pam minlen')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'minlen = 14',
                  'match'  => '^#?minlen',
                )
              is_expected.to contain_file_line('pam minclass')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'minclass = 4',
                  'match'  => '^#?minclass',
                )

              is_expected.to contain_file_line('pam enforcing')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'enforcing = 1',
                  'match'  => '^#?enforcing',
                )

              is_expected.to contain_pam('pam-common-password-requisite')
                .with(
                  'ensure'    => 'present',
                  'service'   => 'common-password',
                  'type'      => 'password',
                  'control'   => 'requisite',
                  'module'    => 'pam_pwquality.so',
                  'arguments' => ['retry=3'],
                )

              is_expected.to contain_package('libpam-pwquality')
                .with(
                  'ensure' => 'present',
                )

            elsif os_facts[:osfamily].casecmp('suse').zero?

              is_expected.to contain_pam('pam-common-password-requisite')
                .with(
                  'ensure'    => 'present',
                  'service'   => 'common-password',
                  'type'      => 'password',
                  'control'   => 'requisite',
                  'module'    => 'pam_cracklib.so',
                  'arguments' => ['retry=3', 'minlen=14', 'dcredit=-1', 'ucredit=-1', 'ocredit=-1', 'lcredit=-1'],
                )

            end

          else
            is_expected.not_to contain_file_line('pam minlen')
            is_expected.not_to contain_file_line('pam dcredit')
            is_expected.not_to contain_file_line('pam ucredit')
            is_expected.not_to contain_file_line('pam ocredit')
            is_expected.not_to contain_file_line('pam lcredit')
            is_expected.not_to contain_pam('pam-system-auth-requisite')
            is_expected.not_to contain_pam('pam-password-auth-requisite')
            is_expected.not_to contain_package('libpam-pwquality')
          end
        }
      end
    end
  end
end

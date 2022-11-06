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
            'dictcheck' => true,
            'difok' => 8,
            'maxrepeat' => 3,
            'maxclassrepeat' => 4,
          }
        end

        it {
          is_expected.to compile

          if enforce
            if os_facts[:os]['family'].casecmp('redhat').zero?

              is_expected.not_to contain_package('libpam-pwquality')

              is_expected.to contain_file_line('pam minlen')
                .with(
                  'ensure'             => 'present',
                  'path'               => '/etc/security/pwquality.conf',
                  'line'               => 'minlen = 14',
                  'match'              => '^#? ?minlen',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam dcredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'dcredit = -1',
                  'match'  => '^#? ?dcredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam ucredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'ucredit = -1',
                  'match'  => '^#? ?ucredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam ocredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'ocredit = -1',
                  'match'  => '^#? ?ocredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam lcredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'lcredit = -1',
                  'match'  => '^#? ?lcredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam dictcheck')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'dictcheck = 1',
                  'match'  => '^#? ?dictcheck',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam difok')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'difok = 8',
                  'match'  => '^#? ?difok',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam maxrepeat')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'maxrepeat = 3',
                  'match'  => '^#? ?maxrepeat',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam maxclassrepeat')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'maxclassrepeat = 4',
                  'match'  => '^#? ?maxclassrepeat',
                  'append_on_no_match' => true,
                )

              if os_facts[:os]['release']['major'] == '7'
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
              end

              if os_facts[:os]['release']['major'] > '7'

                is_expected.to contain_pam('authselect configure pw requirements in system-auth')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'system-auth',
                    'type'      => 'password',
                    'control'   => 'requisite',
                    'module'    => 'pam_pwquality.so',
                    'arguments' => ['try_first_pass', 'retry=3', 'enforce-for-root', 'local_users_only', 'remember=5'],
                    'target'    => '/etc/authselect/custom/testprofile/system-auth',
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_pam('authselect configure pw requirements in password-auth')
                  .with(
                    'ensure'    => 'present',
                    'service'   => 'password-auth',
                    'type'      => 'password',
                    'control'   => 'requisite',
                    'module'    => 'pam_pwquality.so',
                    'arguments' => ['try_first_pass', 'retry=3', 'enforce-for-root', 'local_users_only', 'remember=5'],
                    'target'    => '/etc/authselect/custom/testprofile/password-auth',
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

              end

            elsif os_facts[:os]['family'].casecmp('debian').zero?

              is_expected.to contain_file_line('pam dcredit')
                .with(
                    'ensure' => 'present',
                    'path'   => '/etc/security/pwquality.conf',
                    'line'   => 'dcredit = -1',
                    'match'  => '^#? ?dcredit',
                    'append_on_no_match' => true,
                  )

              is_expected.to contain_file_line('pam ucredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'ucredit = -1',
                  'match'  => '^#? ?ucredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam ocredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'ocredit = -1',
                  'match'  => '^#? ?ocredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam lcredit')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'lcredit = -1',
                  'match'  => '^#? ?lcredit',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam minlen')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'minlen = 14',
                  'match'  => '^#? ?minlen',
                  'append_on_no_match' => true,
                )
              is_expected.to contain_file_line('pam minclass')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'minclass = 4',
                  'match'  => '^#? ?minclass',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam enforcing')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'enforcing = 1',
                  'match'  => '^#? ?enforcing',
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('pam dictcheck')
                .with(
                'ensure' => 'present',
                'path'   => '/etc/security/pwquality.conf',
                'line'   => 'dictcheck = 1',
                'match'  => '^#? ?dictcheck',
                'append_on_no_match' => true,
              )

              is_expected.to contain_file_line('pam difok')
                .with(
                  'ensure' => 'present',
                  'path'   => '/etc/security/pwquality.conf',
                  'line'   => 'difok = 8',
                  'match'  => '^#? ?difok',
                  'append_on_no_match' => true,
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
                  'ensure' => 'installed',
                )

            elsif os_facts[:os]['family'].casecmp('suse').zero?

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
            is_expected.not_to contain_file_line('pam dictcheck')
            is_expected.not_to contain_file_line('pam difok')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::umask_setting' do
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
              umask: true,
              authselect: {
                profile: 'testprofile',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'default_umask' => '027',
          }
        end

        it {
          is_expected.to compile

          if enforce

            if os_facts[:os]['family'].casecmp('debian').zero?

              is_expected.to contain_file_line('login.defs')
                .with(
                  'path'  => '/etc/login.defs',
                  'line'  => 'UMASK           027',
                  'match' => '^UMASK',
                  'append_on_no_match' => true,
                  'multiple' => true,
                )

              is_expected.to contain_file_line('login.defs-usergroups')
                .with(
                  'path'               => '/etc/login.defs',
                  'line'               => 'USERGROUPS_ENAB no',
                  'match'              => '^USERGROUPS_ENAB',
                  'append_on_no_match' => true,
                )

              if os_facts[:os]['name'].casecmp('debian').zero?
                is_expected.to contain_file_line('umask-in-bashrc')
                  .with(
                    'path'               => '/etc/bash.bashrc',
                    'line'               => 'umask 027',
                    'match'              => '^\s*umask',
                    'append_on_no_match' => true,
                    'multiple'           => true,
                  )

                is_expected.to contain_file_line('profile')
                  .with(
                    'ensure'             => 'present',
                    'path'               => '/etc/profile',
                    'line'               => 'umask 027',
                    'match'              => '^\s*umask\s+\d+',
                    'multiple'           => true,
                    'append_on_no_match' => true,
                  )
              else
                is_expected.to contain_file_line('profile')
                  .with(
                    'ensure' => 'absent',
                    'path'     => '/etc/profile',
                    'match'    => '^\s*umask\s+\d+',
                    'multiple' => true,
                    'match_for_absence' => true,
                  )
              end

            elsif os_facts[:os]['family'].casecmp('redhat').zero?

              is_expected.to contain_file_line('bashrc')
                .with(
                  'path'     => '/etc/bashrc',
                  'line'     => '    [ `umask` -eq 0 ] && umask 027',
                  'match'    => '^\s+\[ `umask` -eq 0 \] \&\& umask',
                  'multiple' => true,
                )

              is_expected.to contain_file_line('csh.cshrc')
                .with(
                  'path'     => '/etc/csh.cshrc',
                  'line'     => '    umask 027',
                  'match'    => '^\s+umask\s+\d+',
                  'multiple' => true,
                )

              is_expected.to contain_file_line('profile')
                .with(
                  'path'     => '/etc/profile',
                  'line'     => 'umask 027',
                  'match'    => '^umask\s+\d+',
                  'multiple' => true,
                  'append_on_no_match' => true,
                )

              is_expected.to contain_file_line('login.defs')
                .with(
                  'path'  => '/etc/login.defs',
                  'line'  => 'UMASK           027',
                  'match' => '^\s*UMASK\s+\d+',
                  'append_on_no_match' => true,
                  'multiple' => true,
                )

              is_expected.to contain_file_line('login.defs-usergroups')
                .with(
                  'path'               => '/etc/login.defs',
                  'line'               => 'USERGROUPS_ENAB no',
                  'match'              => '^\s*USERGROUPS_ENAB\s*yes',
                  'append_on_no_match' => true,
                )

            elsif os_facts[:os]['family'].casecmp('suse').zero?

            end

            unless os_facts[:os]['family'].casecmp('suse').zero?

              is_expected.to contain_file('/etc/profile.d/set_umask.sh')
                .with(
                  'ensure'  => 'file',
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )

              if os_facts[:os]['release']['major'] == '8' &&
                 (os_facts[:os]['name'].casecmp('centos').zero? ||
                  os_facts[:os]['name'].casecmp('almalinux').zero? ||
                  os_facts[:os]['name'].casecmp('rocky').zero?)

                is_expected.to contain_file_line('umask in system-auth')
                  .with(
                    'path'               => '/etc/authselect/custom/testprofile/system-auth',
                    'line'               => 'session     optional                                     pam_umask.so',
                    'match'              => '^session\s+optional\s+pam_umask.so',
                    'append_on_no_match' => true,
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.to contain_file_line('umask in password-auth')
                  .with(
                    'path'               => '/etc/authselect/custom/testprofile/password-auth',
                    'line'               => 'session     optional                                     pam_umask.so',
                    'match'              => '^session\s+optional\s+pam_umask.so',
                    'append_on_no_match' => true,
                  )
                  .that_notifies('Exec[authselect-apply-changes]')

                is_expected.not_to contain_pam('pam umask system-auth')
                is_expected.not_to contain_pam('pam umask password-auth')
              else
                is_expected.not_to contain_file_line('umask in system-auth')
                is_expected.not_to contain_file_line('umask in password-auth')

                if os_facts[:os]['name'].casecmp('ubuntu').zero? || os_facts[:os]['name'].casecmp('debian').zero? ||
                   (os_facts[:os]['name'].casecmp('redhat').zero? && os_facts[:os]['release']['major'] >= '9') ||
                   (os_facts[:os]['name'].casecmp('rocky').zero? && os_facts[:os]['release']['major'] >= '9') ||
                   (os_facts[:os]['name'].casecmp('almalinux').zero? && os_facts[:os]['release']['major'] >= '9')
                  is_expected.to contain_pam('pam umask common-session')
                    .with(
                      'ensure'  => 'present',
                      'service' => 'common-session',
                      'type'    => 'session',
                      'control' => 'optional',
                      'module'  => 'pam_umask.so',
                    )
                else
                  is_expected.to contain_pam('pam umask system-auth')
                    .with(
                      'ensure'  => 'present',
                      'service' => 'system-auth',
                      'type'    => 'session',
                      'control' => 'optional',
                      'module'  => 'pam_umask.so',
                    )

                  is_expected.to contain_pam('pam umask password-auth')
                    .with(
                      'ensure'  => 'present',
                      'service' => 'password-auth',
                      'type'    => 'session',
                      'control' => 'optional',
                      'module'  => 'pam_umask.so',
                    )
                end
              end
            end

          else
            is_expected.not_to contain_file_line('bashrc')
            is_expected.not_to contain_file_line('profile')
            is_expected.not_to contain_file_line('login.defs')
            is_expected.not_to contain_file_line('csh.cshrc')
          end
        }
      end
    end
  end
end

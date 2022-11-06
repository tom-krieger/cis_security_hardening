# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sshd_limit_access' do
  let(:pre_condition) do
    <<-EOF
    exec { 'reload-sshd':
      command     => 'systemctl reload sshd',
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
            'cis_security_hardening' => {
              'sshd' => {
                'pub_key_files_status' => false,
                'pub_key_files' => {
                  '/etc/ssh/ssh_host_ecdsa_key.pub' => {
                    'combined' => '0-0-420',
                    'gid' => '0',
                    'mode' => '420',
                    'uid' => '0',
                  },
                },
                'package' => true,
                'banner' => 'none',
                '/etc/ssh/sshd_config' => {
                  'uid' => 1,
                  'gig' => 1,
                  'mode' => 222,
                },
                'permitemptypasswords' => 'yes',
                'protocol' => '1',
                'hostbasedauthentication' => 'yes',
                'ignorerhosts' => 'no',
                'allowusers' => 'none',
                'allowgroups' => 'none',
                'denyusers' => 'none',
                'denygroups' => 'none',
                'logingracetime' => 90,
                'loglevel' => 'WARN',
                'macs' => ['hmm'],
                'maxauthtries' => '5',
                'permitrootlogin' => 'yes',
                'clientaliveinterval' => 400,
                'clientalivecountmax' => 3,
                'permituserenvironment' => 'yes',
              },
            },
          )
        end

        let(:params) do
          {
            'enforce' => enforce,
            'allow_users' => ['test1'],
            'allow_groups' => ['test1'],
            'deny_users' => ['test2'],
            'deny_groups' => ['test2'],
          }
        end

        it {
          is_expected.to compile

          if enforce
            path = if os_facts[:os]['name'] == 'SLES' && os_facts[:os]['release']['major'] == '12'
                     '/usr/etc/ssh/sshd_config'
                   else
                     '/etc/ssh/sshd_config'
                   end
            is_expected.to contain_file_line('ssh-allow-users')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'AllowUsers test1',
                'match'  => '^#?AllowUsers',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.to contain_file_line('ssh-allow-groups')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'AllowGroups test1',
                'match'  => '^#?AllowGroups',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.to contain_file_line('ssh-deny-users')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'DenyUsers test2',
                'match'  => '^#?DenyUsers',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.to contain_file_line('ssh-deny-groups')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'DenyGroups test2',
                'match'  => '^#?DenyGroups',
              )
              .that_notifies('Exec[reload-sshd]')
          else
            is_expected.not_to contain_file_line('ssh-allow-users')
            is_expected.not_to contain_file_line('ssh-allow-groups')
            is_expected.not_to contain_file_line('ssh-deny-users')
            is_expected.not_to contain_file_line('ssh-deny-groups')

          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sshd_empty_passwords' do
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
          }
        end

        it {
          is_expected.to compile

          if enforce
            path = if os_facts[:operatingsystem] == 'SLES' && os_facts[:operatingsystemmajrelease] == '12'
                     '/usr/etc/ssh/sshd_config'
                   else
                     '/etc/ssh/sshd_config'
                   end
            is_expected.to contain_file_line('sshd-empty-passwords')
              .with(
                'ensure' => 'present',
                'path'   => path,
                'line'   => 'PermitEmptyPasswords no',
                'match'  => '^#?PermitEmptyPasswords.*',
              )
              .that_notifies('Exec[reload-sshd]')
          else
            is_expected.not_to contain_file_line('sshd-empty-passwords')
          end
        }
      end
    end
  end
end

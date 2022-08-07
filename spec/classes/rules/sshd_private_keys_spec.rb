# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sshd_private_keys' do
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
                'priv_key_files_status' => false,
                'priv_key_files' => {
                  '/etc/ssh/ssh_host_ecdsa_key' => {
                    'combined' => '0-997-416',
                    'gid' => '997',
                    'mode' => '416',
                    'uid' => '0',
                  },
                  '/etc/ssh/ssh_host_ed25519_key' => {
                    'combined' => '0-0-384',
                    'gid' => '0',
                    'mode' => '384',
                    'uid' => '0',
                  },
                  '/etc/ssh/ssh_host_rsa_key' => {
                    'combined' => '0-0-384',
                    'gid' => '0',
                    'mode' => '384',
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
            is_expected.to contain_file('/etc/ssh/ssh_host_ecdsa_key')
              .with(
                'owner' => 'root',
                'group' => 'root',
                'mode'  => '0600',
              )
            is_expected.to contain_file('/etc/ssh/ssh_host_ed25519_key')
              .with(
                'owner' => 'root',
                'group' => 'root',
                'mode'  => '0600',
              )
            is_expected.to contain_file('/etc/ssh/ssh_host_rsa_key')
              .with(
                'owner' => 'root',
                'group' => 'root',
                'mode'  => '0600',
              )
          else
            is_expected.not_to contain_file('/etc/ssh/ssh_host_ecdsa_key')
            is_expected.not_to contain_file('/etc/ssh/ssh_host_ed25519_key')
            is_expected.not_to contain_file('/etc/ssh/ssh_host_rsa_key')
          end
        }
      end
    end
  end
end

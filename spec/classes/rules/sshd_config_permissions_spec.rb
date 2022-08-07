# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sshd_config_permissions' do
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
        let(:facts) { os_facts }
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
            is_expected.to contain_file(path)
              .with(
                'ensure' => 'file',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )
          else
            is_expected.not_to contain_file('/etc/ssh/sshd_config')
          end
        }
      end
    end
  end
end

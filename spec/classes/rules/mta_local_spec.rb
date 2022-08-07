# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::mta_local' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge!(
            'cis_security_hardening' => {
              'postfix' => 'yes',
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
            is_expected.to contain_file_line('mta-loca-config')
              .with(
                'path'     => '/etc/postfix/main.cf',
                'line'     => 'inet_interfaces = loopback-only',
                'match'    => 'inet_interfaces\s*=',
                'multiple' => true,
              )
              .that_notifies('Exec[restart postfix]')

            is_expected.to contain_exec('restart postfix')
              .with(
                'command'     => 'systemctl restart postfix',
                'path'        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
                'refreshonly' => true,
              )
          else
            is_expected.not_to contain_file_line('mta-loca-config')
            is_expected.not_to contain_exec('restart postfix')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::shell_nologin' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'cis_security_hardening' => {
              'accounts' => {
                'no_shell_nologin' => ['test1'],
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
            is_expected.to contain_exec('nologin test1')
              .with(
                'command' => 'usermod -s /sbin/nologin test1',
                'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )
          else
            is_expected.not_to contain_exec('nologin test1')
          end
        }
      end
    end
  end
end

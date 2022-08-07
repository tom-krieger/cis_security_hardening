# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::shadowed_passwords' do
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
            is_expected.to contain_exec('enforce shadowed passwords')
              .with(
                'command' => 'sed -e \'s/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/\' -i /etc/passwd',
                'path'    => ['/bin', '/usr/bin'],
                'unless'  => 'test -z "$(awk -F: \'($2 != "x" ) { print $1 " is not set to shadowed passwords "}\' /etc/passwd)"',
              )
          else
            is_expected.not_to contain_exec('enforce shadowed passwords')
          end
        }
      end
    end
  end
end

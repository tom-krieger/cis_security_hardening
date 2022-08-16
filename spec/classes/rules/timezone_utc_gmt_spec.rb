# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::timezone_utc_gmt' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'timezone' => 'UTC',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_exec('set timezone')
              .with(
                'command' => 'timedatectl set-timezone UTC',
                'path'    => ['/bin', '/usr/bin'],
                'onlyif'  => "test -z \"$(timedatectl status | grep -i 'time zone' | grep UTC)\"",
              )
          else
            is_expected.not_to contain_exec('set timezone')
          end
        }
      end
    end
  end
end

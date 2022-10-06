# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::login_fail_delay' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'fail_delay' => 5,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('fail_delay')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/login.defs',
                'match'              => '^FAIL_DELAY',
                'line'               => 'FAIL_DELAY 5',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('fail_delay')
          end
        }
      end
    end
  end
end

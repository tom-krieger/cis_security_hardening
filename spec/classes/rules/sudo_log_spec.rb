# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sudo_log' do
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
            is_expected.to contain_file_line('sudo logfile')
              .with(
                'path'               => '/etc/sudoers',
                'match'              => 'Defaults.*logfile\s*=',
                'append_on_no_match' => true,
                'line'               => 'Defaults logfile="/var/log/sudo.log"',
                'after'              => '# Defaults specification',
              )
          else
            is_expected.not_to contain_file_line('sudo logfile')
          end
        }
      end
    end
  end
end

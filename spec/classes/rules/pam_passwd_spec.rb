# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::pam_passwd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('pam_passwd')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/pam.d/passwd',
                'match'              => '^password\s+substack\s+system-auth',
                'line'               => 'password   substack     system-auth',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('pam_passwd')
          end
        }
      end
    end
  end
end

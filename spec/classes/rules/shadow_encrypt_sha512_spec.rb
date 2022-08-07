# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::shadow_encrypt_sha512' do
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
                     '/usr/etc/login.defs'
                   else
                     '/etc/login.defs'
                   end
            is_expected.to contain_file_line('login.defs')
              .with(
                'path'  => path,
                'line'  => 'ENCRYPT_METHOD sha512',
                'match' => '^\s*ENCRYPT_METHOD',
                'append_on_no_match' => true,
                'multiple' => true,
              )
          end
        }
      end
    end
  end
end

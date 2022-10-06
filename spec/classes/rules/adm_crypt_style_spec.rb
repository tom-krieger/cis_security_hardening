# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::adm_crypt_style' do
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
            is_expected.to contain_file_line('crypt_style')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/libuser.conf',
                'match'              => '^#?crypt_style =',
                'line'               => 'crypt_style = sha512',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('crypt_style')
          end
        }
      end
    end
  end
end

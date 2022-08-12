# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::limits_maxlogins' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'maxlogins' => 5,
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('set maxlogins')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/security/limits.conf',
                'match'              => "^*\s+hard\s+maxlogins\s+5",
                'line'               => " *\thard\tmaxlogins\t5",
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('set maxlogins')
          end
        }
      end
    end
  end
end

# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::yum_clean_requirements' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:params) do
          {
            'enforce' => enforce,
          }
        end

        let(:facts) { os_facts }

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('yum_clean_requirements_on_remove')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/yum.conf',
                'line'               => 'clean_requirements_on_remove=1',
                'match'              => '^clean_requirements_on_remove',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('yum_clean_requirements_on_remove')
          end
        }
      end
    end
  end
end

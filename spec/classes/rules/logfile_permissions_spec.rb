# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::logfile_permissions' do
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
            is_expected.to contain_file('/var/log')
              .with(
                'ensure'  => 'directory',
                'recurse' => true,
                'mode'    => 'g-wx,o-rwx',
                'ignore'  => ['puppetlabs', 'puppet'],
              )
          else
            is_expected.not_to contain_file('/var/log')
          end
        }
      end
    end
  end
end

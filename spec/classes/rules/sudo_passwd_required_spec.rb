# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::sudo_passwd_required' do
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
            is_expected.to contain_file_line('targetpw')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/sudoers',
                'match'              => '^Defaults !targetpw',
                'line'               => 'Defaults !targetpw',
                'append_on_no_match' => true,
              )

            is_expected.to contain_file_line('rootpw')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/sudoers',
                'match'              => '^Defaults !rootpw',
                'line'               => 'Defaults !rootpw',
                'append_on_no_match' => true,
              )

            is_expected.to contain_file_line('runaspw')
              .with(
                'ensure'             => 'present',
                'path'               => '/etc/sudoers',
                'match'              => '^Defaults !runaspw',
                'line'               => 'Defaults !runaspw',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('targetpw')
            is_expected.not_to contain_file_line('rootpw')
            is_expected.not_to contain_file_line('runaspw')
          end
        }
      end
    end
  end
end

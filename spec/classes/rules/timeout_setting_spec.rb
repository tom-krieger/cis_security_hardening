# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::timeout_setting' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce #{enforce}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'default_timeout' => 900,
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file('/etc/profile.d/shell_timeout.sh')
              .with(
                'ensure'  => 'file',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
              )

            if os_facts[:os]['name'].casecmp('debian').zero?

              is_expected.to contain_file('/etc/profile')
                .with(
                  'ensure'  => 'file',
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )

              is_expected.to contain_file('/etc/bash.bashrc')
                .with(
                  'ensure'  => 'file',
                  'owner'   => 'root',
                  'group'   => 'root',
                  'mode'    => '0644',
                )
            end
          else
            is_expected.not_to contain_file('/etc/profile.d/shell_timeout.sh')
            is_expected.not_to contain_file('/etc/profile')
            is_expected.not_to contain_file('/etc/bash.bashrc')
          end
        end
      end
    end
  end
end

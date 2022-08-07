# frozen_string_literal: true

require 'spec_helper'

postrun_options = [true, false]

describe 'cis_security_hardening::config' do
  on_supported_os.each do |os, os_facts|
    postrun_options.each do |postrun|
      context "on #{os} with postrun = #{postrun}" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'update_postrun_command' => postrun,
            'fact_upload_command'    => '/usr/share/cis_security_hardening/bin/fact_upload.sh',
          }
        end

        it {
          is_expected.to compile

          is_expected.to contain_file('/usr/share/cis_security_hardening')
            .with(
              'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0700',
            )
          is_expected.to contain_file('/usr/share/cis_security_hardening/logs')
            .with(
              'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0700',
            )
          is_expected.to contain_file('/usr/share/cis_security_hardening/data')
            .with(
              'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0700',
            )
          is_expected.to contain_file('/usr/share/cis_security_hardening/bin')
            .with(
              'ensure' => 'directory',
              'owner'  => 'root',
              'group'  => 'root',
              'mode'   => '0700',
            )

          is_expected.to contain_file('/usr/share/cis_security_hardening/bin/fact_upload.sh')
            .with(
            'ensure'  => 'file',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0700',
          )

          if postrun
            is_expected.to contain_file_line('append postrun command agent')
              .with(
                'path'               => '/etc/puppetlabs/puppet/puppet.conf',
                'after'              => '[agent]',
                'match'              => 'postrun_command\s*=',
                'line'               => 'postrun_command = /usr/share/cis_security_hardening/bin/fact_upload.sh',
                'append_on_no_match' => true,
              )

            is_expected.to contain_file_line('append postrun command main')
              .with(
                'path'               => '/etc/puppetlabs/puppet/puppet.conf',
                'after'              => 'certname\s*=.*',
                'match'              => 'postrun_command\s*=',
                'line'               => 'postrun_command = /usr/share/cis_security_hardening/bin/fact_upload.sh',
                'append_on_no_match' => true,
              )
          else
            is_expected.not_to contain_file_line('append postrun command main')
            is_expected.not_to contain_file_line('append postrun command agent')
          end
        }
      end
    end
  end
end

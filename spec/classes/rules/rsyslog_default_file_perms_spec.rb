# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rsyslog_default_file_perms' do
  let(:pre_condition) do
    <<-EOF
    package { 'rsyslog':
      ensure => installed,
    }
    exec { 'reload-rsyslog':
      command     => 'pkill -HUP rsyslog',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
    EOF
  end

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
            is_expected.to contain_file_line('rsyslog-filepermissions')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/rsyslog.conf',
                'line'   => '$FileCreateMode 0640',
                'match'  => '^\$FileCreateMode.*',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/')
              .with(
                'ensure'  => 'directory',
                'recurse' => true,
                'mode'    => '0640',
              )
          else
            is_expected.not_to contain_file_line('rsyslog-filepermissions')
            is_expected.not_to contain_file('/etc/rsyslog.d/')
          end
        }
      end
    end
  end
end

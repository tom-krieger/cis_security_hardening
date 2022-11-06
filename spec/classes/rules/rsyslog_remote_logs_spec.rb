# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rsyslog_remote_logs' do
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
      context "on #{os} with enforce = #{enforce} and remote host" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'remote_log_host' => '10.10.10.10',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file_line('rsyslog-remote-log-host')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/rsyslog.conf',
                'line'   => '*.* @@10.10.10.10',
                'match'  => '^\*\.\* \@\@.*',
              )
              .that_notifies('Exec[reload-rsyslog]')
          else
            is_expected.not_to contain_file_line('rsyslog-remote-log-host')
          end
        }
      end

      context "on #{os} with enforce = #{enforce} and no remote host" do
        let(:facts) { os_facts }
        let(:params) do
          {
            'enforce' => enforce,
            'remote_log_host' => '',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_echo('no remote log host warning')
              .with(
                  'message'  => 'You have not defined a remote log host, remote syslog is not activated therefore',
                  'loglevel' => 'warning',
                  'withpath' => false,
                )
          else
            is_expected.not_to contain_echo('no remote log host warning')
          end

          is_expected.not_to contain_file_line('rsyslog-remote-log-host')
        }
      end
    end
  end
end

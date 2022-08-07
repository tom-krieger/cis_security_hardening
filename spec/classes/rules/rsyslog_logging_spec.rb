# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]

describe 'cis_security_hardening::rules::rsyslog_logging' do
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
            'log_config' => {
              'emerg' => {
                'src' => '*.emerg',
                'dst' => '*.emerg',
              },
              'mail' => {
                'src' => 'mail.*',
                'dst' => '-/var/log/mail',
              },
              'kern' => {
                'src' => 'kern.*',
                'dst' => '-/var/log/kern.log',
              },
              'messages' => {
                'src' => '*.info;mail.none;authpriv.none;cron.none;local0.none',
                'dst' => '/var/log/messages',
              },
              'cron' => {
                'src' => 'cron.*',
                'dst' => '/var/log/cron',
              },
              'secure' => {
                'src' => '*.info;mail.none;authpriv.none;cron.none;local0.none',
                'dst' => '-/var/log/secure',
              },
              'spooler' => {
                'src' => 'uucp,news.crit',
                'dst' => '/var/log/spooler',
              },
              'boot' => {
                'src' => 'local7.*',
                'dst' => '/var/log/boot.log',
              },
              'ldap' => {
                'src' => 'local4.*',
                'dst' => '/var/log/ldap.log',
              },
              'debug' => {
                'src' => '*.debug',
                'dst' => '/var/log/debug',
              },
              'daemon' => {
                'src' => 'daemon.*',
                'dst' => '/var/log/daemon.log',
              },
            },
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_file('/etc/rsyslog.d/emerg.conf')
              .with(
                'ensure'  => 'file',
                'content' => '*.emerg *.emerg',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/mail.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'mail.* -/var/log/mail',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/messages.conf')
              .with(
                'ensure'  => 'file',
                'content' => '*.info;mail.none;authpriv.none;cron.none;local0.none /var/log/messages',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/cron.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'cron.* /var/log/cron',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/secure.conf')
              .with(
                'ensure'  => 'file',
                'content' => '*.info;mail.none;authpriv.none;cron.none;local0.none -/var/log/secure',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/spooler.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'uucp,news.crit /var/log/spooler',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/boot.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'local7.* /var/log/boot.log',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/ldap.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'local4.* /var/log/ldap.log',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/daemon.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'daemon.* /var/log/daemon.log',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/debug.conf')
              .with(
                'ensure'  => 'file',
                'content' => '*.debug /var/log/debug',
              )
              .that_notifies('Exec[reload-rsyslog]')

            is_expected.to contain_file('/etc/rsyslog.d/kern.conf')
              .with(
                'ensure'  => 'file',
                'content' => 'kern.* -/var/log/kern.log',
              )
              .that_notifies('Exec[reload-rsyslog]')
          else
            is_expected.not_to contain_file('/etc/rsyslog.d/emerg.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/mailall.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/kern.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/messages.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/cron.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/secure.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/spooler.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/boot.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/ldap.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/daemon.conf')
            is_expected.not_to contain_file('/etc/rsyslog.d/debug.conf')
          end
        }
      end
    end
  end
end

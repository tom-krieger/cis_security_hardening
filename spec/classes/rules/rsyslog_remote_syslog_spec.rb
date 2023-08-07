# frozen_string_literal: true

require 'spec_helper'

enforce_options = [true, false]
loghost_options = [true, false]

describe 'cis_security_hardening::rules::rsyslog_remote_syslog' do
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
      loghost_options.each do |is_loghost|
        loghost_param = !is_loghost
        context "on #{os} with enforce = #{enforce} and loghost = #{is_loghost}" do
          let(:facts) do
            os_facts.merge(
              'cis_security_hardening' => {
                'syslog' => {
                  'rsyslog' => {
                    'filepermissions' => '0755',
                    'loghost' => loghost_param,
                  },
                },
              },
            )
          end
          let(:params) do
            {
              'enforce' => enforce,
              'is_loghost' => is_loghost,
            }
          end

          it {
            is_expected.to compile

            if enforce
              if is_loghost
                is_expected.to contain_file_line('rsyslog.conf add ModLoad')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/rsyslog.conf',
                    'line'   => '$ModLoad imtcp',
                    'match'  => '^#.*\$ModLoad.*imtcp',
                    'append_on_no_match' => true,
                  )
                  .that_notifies('Exec[reload-rsyslog]')

                is_expected.to contain_file_line('rsyslog.conf add InputTCPServerRun')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/rsyslog.conf',
                    'line'   => '$InputTCPServerRun 514',
                    'match'  => '\$InputTCPServerRun',
                  )
                  .that_notifies('Exec[reload-rsyslog]')
              else
                is_expected.to contain_file_line('rsyslog.conf remove ModLoad')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/rsyslog.conf',
                    'line'   => '# $ModLoad imtcp',
                    'match'  => '^\$ModLoad.*imtcp',
                  )
                  .that_notifies('Exec[reload-rsyslog]')

                is_expected.to contain_file_line('rsyslog.conf remove InputTCPServerRun')
                  .with(
                    'ensure' => 'present',
                    'path'   => '/etc/rsyslog.conf',
                    'line'   => '#$InputTCPServerRun 514',
                    'match'  => '\$InputTCPServerRun',
                  )
                  .that_notifies('Exec[reload-rsyslog]')
              end
            elsif is_loghost
              is_expected.not_to contain_file_line('rsyslog.conf add ModLoad')
              is_expected.not_to contain_file_line('rsyslog.conf add InputTCPServerRun')
            else
              is_expected.not_to contain_file_line('rsyslog.conf remove ModLoad')
              is_expected.not_to contain_file_line('rsyslog.conf remove InputTCPServerRun')
            end
          }
        end
      end
    end
  end
end

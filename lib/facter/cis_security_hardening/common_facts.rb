# frozen_string_literal: true

require 'facter/cis_security_hardening/utils/check_puppet_postrun_command'
require 'facter/cis_security_hardening/utils/read_auditd_data'
require 'facter/cis_security_hardening/utils/read_wlan_data'
require 'facter/cis_security_hardening/utils/read_local_users'
require 'facter/cis_security_hardening/utils/check_value_string'
require 'facter/cis_security_hardening/utils/read_sshd_config'
require 'facter/cis_security_hardening/utils/check_value_integer'
require 'facter/cis_security_hardening/utils/read_open_ports'
require 'facter/cis_security_hardening/utils/read_nfs_filesystems'

def common_facts(os, _distid, _release)
  facts = {}

  # check agent port run command
  facts['puppet_agent_postrun'] = check_puppet_postrun_command

  # get auditd data
  facts['auditd'] = read_auditd_data

  # get wlan information
  facts.merge!(read_wlan_data)

  # get local users
  facts['local_users'] = read_local_users

  # get information about password dates
  pw_data = {}
  val = Facter::Core::Execution.exec("grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_max_days'] = check_value_integer(val, 99_999)
  pw_data['pass_max_days_status'] = if pw_data['pass_max_days'] > 365
                                      true
                                    else
                                      false
                                    end
  val = Facter::Core::Execution.exec("grep ^PASS_MIN_DAYS /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_min_days'] = check_value_string(val, '0')
  pw_data['pass_min_days_status'] = pw_data['pass_min_days'] < '7'
  val = Facter::Core::Execution.exec("grep ^PASS_WARN_AGE /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_warn_age'] = check_value_string(val, '0')
  pw_data['pass_warn_age_status'] = pw_data['pass_warn_age'] < '7'
  val = Facter::Core::Execution.exec('useradd -D | grep INACTIVE | cut -f 2 -d =')
  pw_data['inactive'] = check_value_string(val, '-1').to_i
  pw_data['inactive_status'] = pw_data['inactive'] < 30
  ret = false
  facts['local_users'].each do |_user, data|
    unless data['password_date_valid']
      ret = true
    end
  end
  pw_data['pw_change_in_future'] = ret
  pw_data = {}
  val = Facter::Core::Execution.exec("grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_max_days'] = check_value_integer(val, 99_999)
  pw_data['pass_max_days_status'] = if pw_data['pass_max_days'] > 365
                                      true
                                    else
                                      false
                                    end
  val = Facter::Core::Execution.exec("grep ^PASS_MIN_DAYS /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_min_days'] = check_value_string(val, '0')
  pw_data['pass_min_days_status'] = pw_data['pass_min_days'] < '7'
  val = Facter::Core::Execution.exec("grep ^PASS_WARN_AGE /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_warn_age'] = check_value_string(val, '0')
  pw_data['pass_warn_age_status'] = pw_data['pass_warn_age'] < '7'
  val = Facter::Core::Execution.exec('useradd -D | grep INACTIVE | cut -f 2 -d =')
  pw_data['inactive'] = check_value_string(val, '-1').to_i
  pw_data['inactive_status'] = pw_data['inactive'] < 30
  ret = false
  facts['local_users'].each do |_user, data|
    unless data['password_date_valid']
      ret = true
    end
  end
  pw_data['pw_change_in_future'] = ret
  facts['pw_data'] = pw_data

  # get sshd information
  facts['sshd'] = read_sshd_config(false)

  # read result from cronjob and create fact
  files = []
  if File.exist?('/usr/share/cis_security_hardening/data/world-writable-files.txt')
    text = File.open('/usr/share/cis_security_hardening/data/world-writable-files.txt').read
    text.gsub!(%r{\r\n?}, "\n")
    files = text.split("\n")
  end
  facts['world_writable'] = files
  facts['world_writable_count'] = files.count

  # check for postfix
  pkgs = if os.casecmp('suse').zero? || os.casecmp('redhat').zero?
           Facter::Core::Execution.exec('rpm -q postfix 2>/dev/null')
         elsif os.casecmp('debian').zero?
           Facter::Core::Execution.exec('dpkg -l | grep postfix | awk \'{print $2;}\'')
         else
           nil
         end
  facts['postfix'] = if pkgs.nil? || pkgs.empty? || pkgs.include?('not installed')
                       'no'
                     else
                       'yes'
                     end

  logrotate_conf = {}
  val = Facter::Core::Execution.exec('grep -Es "^\s*create\s+\S+" /etc/logrotate.conf /etc/logrotate.d/* | grep -E -v "\s(0)?[0-6][04]0\s"')
  unless val.nil? || val.empty?
    val.split("\n").each do |line|
      data = line.split(%r{:})
      file = data[0]
      data_rotate = data[1].split(%r{\s+})
      entry = {
        'action' => data_rotate[1],
        'mode'   => data_rotate[2],
        'user'   => data_rotate[3],
        'group'  => data_rotate[4],
      }
      logrotate_conf[file] = entry
    end
  end
  facts['logrotate_conf'] = logrotate_conf

  facts['open_ports'] = read_open_ports

  facts['nfs_file_systems'] = read_nfs_filesystems

  facts['efi'] = File.directory?('/sys/firmware/efi')

  facts
end

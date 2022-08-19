# frozen_string_literal: true

def read_auditd_data
  auditd = {}

  cmd = 'find /usr -xdev \\( -perm -4000 -o -perm -2000 \\) -type f'
  priv_cmds = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['priv-cmds-list'] = priv_cmds.uniq.sort

  cmd = 'find /etc/audit/ /etc/audit/rules.d -type f 2>/dev/null'
  conf_raw = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['config_files'] = conf_raw.uniq

  cmd = 'find /var/log/audit/ -maxdepth 1 -type f 2>/dev/null'
  files_raw = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['log_files'] = files_raw.uniq

  cmd = "awk '/^\s*UID_MIN/{print $2}' /etc/login.defs"
  val = Facter::Core::Execution.exec(cmd)
  auditd['uid_min'] = if val.nil? || val.empty?
                        '1000'
                      else
                        val.strip.to_s
                      end

  cmd = 'find /etc/audit/ /etc/audit/rules.d -type f 2>/dev/null'
  conf_raw = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['config_files'] = conf_raw.uniq

  cmd = 'find /var/log/audit/ -maxdepth 1 -type f 2>/dev/null'
  files_raw = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['log_files'] = files_raw.uniq

  auditd
end

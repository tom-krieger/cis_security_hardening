# frozen_string_literal: true

def read_auditd_data
  auditd = {}

  priv_cmds = []
  cmd = "find /usr -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | awk '{print \"-a always,exit -S all -F path=\" $1 \" -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged\"; }'"
  rules_raw = Facter::Core::Execution.exec(cmd).split("\n")
  priv_cmds.push(rules_raw)
  auditd['priv-cmds-list'] = priv_cmds.uniq

  cmd = 'find /etc/audit/ /etc/audit/rules.d -type f 2>/dev/null'
  conf_raw = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['config_files'] = conf_raw.uniq

  cmd = 'find /var/log/audit/ -maxdepth 1 -type f 2>/dev/null'
  files_raw = Facter::Core::Execution.exec(cmd).split("\n")
  auditd['log_files'] = files_raw.uniq

  auditd
end

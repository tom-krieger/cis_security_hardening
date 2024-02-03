# frozen_string_literal: true

# read auditd configuration data
def read_auditd_data
  auditd = {}

  files = []
  if File.exist?('/usr/share/cis_security_hardening/data/auditd_priv_cmds.txt')
    text = File.open('/usr/share/cis_security_hardening/data/auditd_priv_cmds.txt').read
    text.gsub!(%r{\r\n?}, "\n")
    files = text.split("\n")
  end
  auditd['priv-cmds-list'] = files

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

  auditd
end

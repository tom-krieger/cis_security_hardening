# frozen_string_literal: true

require 'pp'

def read_sshd_config(long = true)
  sshd = {}
  if long
    sshdcmd = if File.exist?('/sbin/sshd')
                '/sbin/sshd'
              else
                '/usr/sbin/sshd'
              end
    val = Facter::Core::Execution.exec("grep '^/s*CRYPTO_POLICY=' /etc/sysconfig/sshd'")
    sshd['crypto_policy'] = check_value_string(val, 'none')
    sshd['package'] = check_package_installed('openssh-server')
    sshd['/etc/ssh/sshd_config'] = read_file_stats('/etc/ssh/sshd_config')

    sshd_values = ['loglevel', 'x11forwarding', 'maxauthtries', 'maxstartups', 'maxsessions',
                   'ignorerhosts', 'hostbasedauthentication', 'permitrootlogin', 'permitemptypasswords', 'permituserenvironment',
                   'clientaliveinterval', 'clientalivecountmax', 'logingracetime', 'banner', 'usepam', 'allowtcpforwarding']

    sshd_values.each do |sshd_value|
      val = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i #{sshd_value} | awk '{print $2;}'")
      unless val.nil? || val.empty?
        val.strip!
      end
      sshd[sshd_value] = check_value_string(val, 'none')
    end

    sshd['macs'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^MACs\" | awk '{print $2;}'").strip.split(%r{\,})
    sshd['ciphers'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^ciphers\" | awk '{print $2;}'").strip.split(%r{\,})
    sshd['kexalgorithms'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^kexalgorithms\" | awk '{print $2;}'").strip.split(%r{\,})
    sshd['allowusers'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^AllowUsers\" | awk '{print $2;}'").strip.split("\n")
    sshd['allowgroups'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^AllowGroups\" | awk '{print $2;}'").strip.split("\n")
    sshd['denyusers'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^DenyUsers\" | awk '{print $2;}'").strip.split("\n")
    sshd['denygroups'] = Facter::Core::Execution.exec("#{sshdcmd} -T | grep -i \"^DenyGroups\" | awk '{print $2;}'").strip.split("\n")
    sshd['protocol'] = check_value_string(Facter::Core::Execution.exec('grep "^Protocol" /etc/ssh/sshd_config | awk \'{print $2;}\'').strip, 'none')
  end

  val = Facter::Core::Execution.exec("find /etc/ssh -xdev -type f -name 'ssh_host_*_key'")
  sshd['priv_key_files'] = if val.nil? || val.empty?
                             {}
                           else
                             key_files = {}
                             val.split("\n").each do |ssh_key_file|
                               key_files[ssh_key_file] = read_file_stats(ssh_key_file)
                             end
                             key_files
                           end
  status = true
  sshd['priv_key_files'].each do |_ssh_key_file, data|
    if data['combined'] != '0-0-384'
      status = false
    end
  end
  sshd['priv_key_files_status'] = status

  val = Facter::Core::Execution.exec("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub'")
  sshd['pub_key_files'] = if val.nil? || val.empty?
                            {}
                          else
                            key_files = {}
                            val.split("\n").each do |ssh_key_file|
                              key_files[ssh_key_file] = read_file_stats(ssh_key_file)
                            end
                            key_files
                          end
  status = true
  sshd['pub_key_files'].each do |_ssk_key_file, data|
    if data['combined'] != '0-0-420'
      status = false
    end
  end
  sshd['pub_key_files_status'] = status

  sshd
end

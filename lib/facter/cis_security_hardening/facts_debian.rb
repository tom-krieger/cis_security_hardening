# frozen_string_literal: true

require 'facter/cis_security_hardening/utils/check_package_installed'
require 'facter/cis_security_hardening/utils/check_value_string'
require 'facter/cis_security_hardening/utils/read_file_stats'
require 'facter/cis_security_hardening/utils/read_iptables_rules'
require 'facter/cis_security_hardening/utils/read_apparmor_data'
require 'pp'

def facts_debian(os, distid, release)
  cis_security_hardening = common_facts(os, distid, release)

  # get apparmor data
  cis_security_hardening[:apparmor] = read_apparmor_data

  # get gnome display manager information
  cis_security_hardening[:gnome_gdm] = File.exist?('/etc/gdm3/greeter.dconf')

  # determine apport installation
  apport = {}
  val = Facter::Core::Execution.exec("dpkg-query -s apport > /dev/null 2>&1 && grep -Psi -- '^\\h*enabled\\h*=\\h*[^0]\\b' /etc/default/apport")
  apport['pkg'] = if !val.nil? && !val.empty?
                    true
                  else
                    false
                  end
  val = Facter::Core::Execution.exec("systemctl is-active apport.service | grep '^active'")
  apport['service'] = if val.nil? || val.empty?
                        false
                      else
                        true
                      end
  cis_security_hardening[:apport] = apport

  # get iptables config
  cis_security_hardening['iptables'] = read_iptables_rules('4')
  cis_security_hardening['ip6tables'] = read_iptables_rules('6')

  # get account informtion
  accounts = {}
  wrong_shell = []
  cmd = "egrep -v \"^\/+\" /etc/passwd | awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $3<1000 && $7!=\"/usr/sbin/nologin\" && $7!=\"/bin/false\") {print}'"
  val = Facter::Core::Execution.exec(cmd)
  unless val.nil? || val.empty?
    val.split("\n").each do |line|
      data = line.split(%r{:})
      wrong_shell.push(data[0])
    end
  end
  accounts['no_shell_nologin'] = wrong_shell
  accounts['no_shell_nologin_count'] = wrong_shell.count
  val = Facter::Core::Execution.exec('grep "^root:" /etc/passwd | cut -f4 -d:')
  accounts['root_gid'] = check_value_string(val, 'none')
  cis_security_hardening['accounts'] = accounts

  # check for x11 packages
  x11 = {}
  pkgs = Facter::Core::Execution.exec('dpkg -l | grep xorg-x1 | awk \'{print $2;}\'')
  x11['installed'] = if pkgs.nil? || pkgs.empty?
                       false
                     else
                       true
                     end
  cis_security_hardening[:x11] = x11

  # check for xdmcp
  cis_security_hardening['xdcmp'] = File.exist?('/etc/gdm3/custom.conf')

  # return results
  cis_security_hardening
end

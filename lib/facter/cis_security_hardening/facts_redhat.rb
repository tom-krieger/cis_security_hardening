# frozen_string_literal: true

require 'facter/cis_security_hardening/utils/check_package_installed'
require 'facter/cis_security_hardening/utils/check_value_string'
require 'facter/cis_security_hardening/utils/read_file_stats'
require 'facter/cis_security_hardening/utils/read_iptables_rules'
require 'facter/cis_security_hardening/utils/read_firewalld_zone_iface'
require 'pp'

# frozen_string_literal: true

def facts_redhat(os, distid, release)
  cis_security_hardening = common_facts(os, distid, release)

  # get authselect config
  if File.exist?('/usr/bin/authselect')
    authselect = {}
    val = Facter::Core::Execution.exec('/usr/bin/authselect current | grep "Profile ID: custom/"')
    authselect['profile'] = if val.nil? || val.empty?
                              'none'
                            elsif val.include?('No existing configuration detected')
                              'none'
                            else
                              m = val.match(%r{Profile ID: custom\/(?<profile>\w*)})
                              if m.nil?
                                'none'
                              else
                                m[:profile]
                              end
                            end

    val = Facter::Core::Execution.exec('/usr/bin/authselect current')
    options = []
    unless val.nil? || val.empty?
      val.split("\n").each do |line|
        next unless line.match?(%r{^\-})

        m = line.match(%r{^\-\s*(?<option>[a-zA-Z0-9\-_]*)})
        unless m.nil?
          options.push(m[:option])
        end
      end
    end

    authselect['current_options'] = options
    val = Facter::Core::Execution.exec('/usr/bin/authselect current | grep with-faillock')
    authselect['faillock'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec('grep with-faillock /etc/authselect/authselect.conf')
    authselect['faillock_global'] = check_value_string(val, 'none')
    avail_features = []
    val = Facter::Core::Execution.exec("/usr/bin/authselect list-features custom/#{authselect['profile']}")
    opts = val.split("\n").each do |opt|
      avail_features.push(opt)
    end
    authselect['available_features'] = avail_features
    cis_security_hardening['authselect'] = authselect
  end

  # get information about crypto policy
  crypto_policy = {}
  if File.exist?('/etc/crypto-policies/config')
    val = Facter::Core::Execution.exec("grep -E -h -i '^\s*(FUTURE|FIPS|DEFAULT)\s*(\s+#.*)?$' /etc/crypto-policies/config")
    crypto_policy['policy'] = check_value_string(val, 'none')
  else
    crypto_policy['policy'] = 'none'
  end
  if File.exist?('/usr/bin/fips-mode-setup')
    val = Facter::Core::Execution.exec('/usr/bin/fips-mode-setup --check')
    crypto_policy['fips_mode'] = if val.nil? || val.empty?
                                   'none'
                                 else
                                   m = val.match(%r{FIPS mode is\s*(?<mode>\w*)\.})
                                   if m.nil?
                                     'none'
                                   else
                                     m[:mode]
                                   end
                                 end
  end
  cis_security_hardening['crypto_policy'] = crypto_policy

  # gather firewalld information
  if File.exist?('/usr/bin/firewall-cmd')
    firewalld = {}
    val = Facter::Core::Execution.exec('firewall-cmd --get-default-zone')
    firewalld['default_zone'] = check_value_string(val, 'none')
    firewalld['default_zone_status'] = if check_value_string(val, 'none') == 'none'
                                         false
                                       else
                                         true
                                       end

    if File.exist?('/usr/bin/nmcli')
      val = Facter::Core::Execution.exec("nmcli -t connection show | awk -F: '{if($4){print $4}}' | while read INT; do firewall-cmd --get-active-zones | grep -B1 $INT; done")
      if val.nil? || val.empty?
        firewalld['zone_iface'] = {}
        firewalld['zone_iface_assigned'] = false
      else
        firewalld = read_firewalld_zone_iface(val, firewalld)
      end
    end

    val = Facter::Core::Execution.exec("firewall-cmd --get-active-zones | awk '!/:/ {print $1}' | while read ZN; do firewall-cmd --list-all --zone=$ZN; done")
    if val.nil? || val.empty?
      firewalld['ports'] = []
      firewalld['services'] = []
    else
      val.split("\n").each do |line|
        # if line.match?(%r{services:})
        if line.include?('services:')
          m = line.match(%r{services:\s*(?<srvs>.*)})
          unless m.nil?
            firewalld['services'] = m[:srvs].gsub(%r{\s+}m, ' ').strip.split(' ')
            firewalld['services_count'] = firewalld['services'].count
          end
        # elsif line.match?(%r{ports:})
        elsif line.include?('ports:')
          m = line.match(%r{ports:\s*(?<ports>.*)})
          unless m.nil?
            firewalld['ports'] = m[:ports].split("\s*")
            firewalld['ports_count'] = firewalld['ports'].count
          end
        end
      end
      firewalld['ports_and_services_status'] = firewalld['ports_count'] != 0 || firewalld['services_count'] != 0
    end
    cis_security_hardening['firewalld'] = firewalld
  end

  # check gnome gdm installation
  cis_security_hardening[:gnome_gdm] = Facter::Core::Execution.exec('rpm -qa | grep gnome') != ''
  val1 = check_value_string(Facter::Core::Execution.exec('grep "user-db:user" /etc/dconf/profile/gdm'), 'none')
  val2 = check_value_string(Facter::Core::Execution.exec('grep "system-db:gdm" /etc/dconf/profile/gdm'), 'none')
  val3 = check_value_string(Facter::Core::Execution.exec('grep "file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm'), 'none')
  cis_security_hardening[:gnome_gdm_conf] = if (val1 == 'none' || val2 == 'none' || val3 == 'none') && cis_security_hardening[:gnome_gdm]
                                              false
                                            else
                                              true
                                            end

  # get iptables config
  cis_security_hardening['iptables'] = read_iptables_rules('4')
  if release > '6'
    cis_security_hardening['ip6tables'] = read_iptables_rules('6')
  end

  # get authselect information
  if File.exist?('/usr/bin/authselect')
    authselect = {}
    val = Facter::Core::Execution.exec('/usr/bin/authselect current | grep "Profile ID: custom/"')
    authselect['profile'] = if val.nil? || val.empty?
                              'none'
                            # elsif val.match?(%r{No existing configuration detected})
                            elsif val.include?('No existing configuration detected')
                              'none'
                            else
                              m = val.match(%r{Profile ID: custom\/(?<profile>\w*)})
                              if m.nil?
                                'none'
                              else
                                m[:profile]
                              end
                            end

    val = Facter::Core::Execution.exec('/usr/bin/authselect current')
    options = []
    unless val.nil? || val.empty?
      val.split("\n").each do |line|
        next unless line.match?(%r{^\-})
        m = line.match(%r{^\-\s*(?<option>[a-zA-Z0-9\-_]*)})
        unless m.nil?
          options.push(m[:option])
        end
      end
    end
    authselect['current_options'] = options
    val = Facter::Core::Execution.exec('/usr/bin/authselect current | grep with-faillock')
    authselect['faillock'] = check_value_string(val, 'none')
    val = Facter::Core::Execution.exec('grep with-faillock /etc/authselect/authselect.conf')
    authselect['faillock_global'] = check_value_string(val, 'none')
    cis_security_hardening['authselect'] = authselect
  end

  # collect accounts data
  accounts = {}
  wrong_shell = []
  min_uid = if release > '6'
              1000
            else
              500
            end

  cmd = "egrep -v \"^\/+\" /etc/passwd | awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $3<#{min_uid} && $7!=\"/sbin/nologin\" && $7!=\"/bin/false\") {print}'"
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
  # do not consider xorg-x11-fonts packages as these are necessary for java
  val = Facter::Core::Execution.exec('rpm -qa xorg-x11* | grep -v xorg-x11-fonts')
  pkgs = val.split("\n")
  x11['packages'] = pkgs
  x11['installed'] = if pkgs.nil? || pkgs.empty?
                       false
                     else
                       true
                     end

  cis_security_hardening[:x11] = x11

  # check systemd-coredump
  pkgs = Facter::Core::Execution.exec('rpm -q systemd-coredump 2>/dev/null')
  cis_security_hardening['systemd-coredump'] = if pkgs.nil? || pkgs.empty? || pkgs.include?('not installed')
                                                 'no'
                                               else
                                                 'yes'
                                               end

  # return results
  cis_security_hardening
end

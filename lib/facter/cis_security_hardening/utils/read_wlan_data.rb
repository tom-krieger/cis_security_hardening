# frozen_string_literal: true

def read_wlan_data
  wlan = []
  data = {}

  if File.exist?('/usr/bin/nmcli')
    val = Facter::Core::Execution.exec('/usr/bin/nmcli radio all 2>&1 | grep -v WIFI')
    if val.nil? || val.empty?
      status = 'disabled'
    elsif val == 'Error: NetworkManager is not running.'
      status = 'disabled'
    else
      m = val.match(%r{^(enabled|disabled)\s*(?<wifi>\w*)\s*(enabled|disabled)})
      status = if m.nil?
                 'disabled'
               else
                 m[:wifi]
               end
    end
    data['wlan_status'] = status
  else
    cnt = 0
    nw = Facter.value(:networking)
    nw['interfaces'].each do |ifname, _data|
      # if ifname.match?(%r{wlan})
      if ifname.include?('wlan')
        cnt += 1
        wlan.push(ifname)
      end
    end
    data['wlan_interfaces'] = wlan
    data['wlan_interfaces_count'] = cnt
  end

  data
end

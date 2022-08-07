# frozen_string_literal: true

def read_firewalld_zone_iface(val, firewalld)
  zone = 'undef'
  iface_assigned = false
  val.split("\n").each do |line|
    if line.match?(%r{^[a-zA-Z0-9]})
      zone = line
    # elsif line.match?(%r{interfaces:})
    elsif line.include?('interfaces:')
      m = line.match(%r{interfaces:\s*(?<ifaces>[a-zA-Z0-9_\-]*)})
      unless m.nil?
        ifaces = m[:ifaces]
        firewalld['zone_iface'] = {}
        firewalld['zone_iface'][zone] = ifaces
        iface_assigned = true
      end
    end
  end
  firewalld['zone_iface_assigned_status'] = iface_assigned

  firewalld
end

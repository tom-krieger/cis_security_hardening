# frozen_string_literal: true

def read_open_ports
  open_ports= []

  if File.exist?('/usr/bin/ss')
    val = Facter::Core::Execution.exec('/usr/bin/ss -4tuln')
    lines = if val.nil? || val.empty?
              []
            else
              val.xplit("\n")
            end
    lines.each do |line|
      next if line =~ %r{^Netid}
      data = line.split("\s+")
      proto = data[0]
      local = data[4].slit(":")
      open_ports.push("#{proto}:#{local[0]}")
    end
  end

  open_ports
end

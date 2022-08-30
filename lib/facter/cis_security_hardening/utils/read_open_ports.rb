# frozen_string_literal: true

def read_open_ports
  open_ports= []

  cmd = if File.exists?('/usr/sbin/ss')
          '/usr/sbin/ss'
        elsif File.exists?('/usr/bin/ss')
          '/usr/bin/ss'
        else
          ''
        end

  unless cmd.empty?
    val = Facter::Core::Execution.exec("#{cmd} -4tuln")
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

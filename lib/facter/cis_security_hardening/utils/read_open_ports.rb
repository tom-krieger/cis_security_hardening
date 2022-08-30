# frozen_string_literal: true

def read_open_ports
  open_ports = []

  cmd = if File.exist?('/usr/sbin/ss')
          '/usr/sbin/ss'
        elsif File.exist?('/usr/bin/ss')
          '/usr/bin/ss'
        else
          ''
        end

  unless cmd.empty?
    val = Facter::Core::Execution.exec("#{cmd} -4tuln")
    lines = if val.nil? || val.empty?
              []
            else
              val.split("\n")
            end
    lines.each do |line|
      next if %r{^Netid}.match?(line)
      data = line.split("\s")
      proto = data[0].strip
      local = data[4].split(':')
      pp local
      port = local[1].strip
      pp port
      open_ports.push("#{proto}:#{port}")
    end
  end

  open_ports
end

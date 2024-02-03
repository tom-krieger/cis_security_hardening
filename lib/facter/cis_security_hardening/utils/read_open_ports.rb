# frozen_string_literal: true

# read open ports
def read_open_ports
  opports = []
  ss_cmd = ''
  cmds = ['/usr/sbin/ss', '/usr/bin/ss', '/bin/ss', '/sbin/ss']
  cmds.each do |cmd|
    if File.exist?(cmd)
      ss_cmd = cmd
    end
  end

  unless ss_cmd.empty?

    val = Facter::Core::Execution.exec("#{ss_cmd} -4tuln")
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
      port = local[1].strip
      if local[0] != '127.0.0.1'
        opports.push("#{proto}:#{port}")
      end
    end
  end

  open_ports = opports.uniq
  open_ports
end

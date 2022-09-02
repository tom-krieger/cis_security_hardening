# frozen_string_literal: true

def read_nfs_filesystems
  nfs_file_systems = {}
  if File.exist?('/etc/fstab')
    val = Facter::Core::Execution.exec("grep -E \"\s+nfs\s+\" /etc/fstab")
    lines = if val.nil? || val.empty?
              []
            else
              val.split("\n")
            end
    lines.each do |line|
      data = line.split("\s")
      next if data.empty?
      nfs_file_systems[data[1]] = {
        'device' => data[0],
        'mountoptions' => data[3]
      }
    end
  end

  nfs_file_systems
end

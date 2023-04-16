# frozen_string_literal: true

def read_nfs_filesystems
  nfs_file_systems = {}
  if File.exist?('/etc/fstab')
    lines = File.readlines('/etc/fstab')
    lines.each do |line|
      data = line.split("\s")
      # next if data.empty? || data[2] !~ %r{nfs}
      next if data.empty? || !data[2].include?('nfs')
      nfs_file_systems[data[1]] = {
        'device' => data[0],
        'mountoptions' => data[3]
      }
    end
  end

  nfs_file_systems
end

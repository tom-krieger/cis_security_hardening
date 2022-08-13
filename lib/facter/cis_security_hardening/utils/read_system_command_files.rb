
def read_system_command_files
  cmd = 'find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c "%n %G" \'{}\' \; 2> /dev/null | grep -v "root$"'
  files_raw = Facter::Core::Execution.exec(cmd).split("\n")
  ret = []
  files_raw.each do |line|
    data = line.split(' ')
    ret.push(data[0])
  end

  ret.uniq
end

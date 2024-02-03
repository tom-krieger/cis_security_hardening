# frozen_string_literal: true

# check if a package isinstalled
# params:
#    opts: rpm options to use
#    pkg:  package name to query
def check_package_installed(pkg, opts = '-q')
  os = Facter.value(:osfamily)
  if (os == 'RedHat') || (os == 'Suse')
    val = Facter::Core::Execution.exec("rpm #{opts} #{pkg}")
  elsif os == 'Debian'
    if opts == '-q'
      opts = ''
    end
    opts = "#{opts} -l"
    val = Facter::Core::Execution.exec("dpkg #{opts} #{pkg} | grep ^ii")
  end

  if val.nil? || val.empty? || val.include?('not installed')
    false
  else
    true
  end
end

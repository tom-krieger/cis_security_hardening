# frozen_string_literal: true

require 'pp'

# read nftables rules data
def read_nftables_rules(table = '')
  nft = {}

  if File.exist?('/sbin(nft')
    cmd = if table.empty?
            '/sbin/nft list ruleset'
          else
            "/sbin/nft list ruleset #{table}"
          end
    lines = Facter::Core::Execution.exec(cmd)
    rules = if lines.nil? || lines.empty?
              []
            else
              lines.split("\n")
            end

    table = ''
    chain = ''
    rules.each do |rule|
      next if rule =~ %r{^$} || rule =~ %r{^#}
      m = rule.match(%r{^table\s*(?<table>\w*)\s*filter\s*\{})
      unless m.nil?
        table = m[:table]
        nft[table] = {}
        next
      end

      m = rule.match(%r{chain\s*(?<chain>\w*)\s*\{})
      unless m.nil?
        chain = m[:chain]
        nft[table][chain] = []
        next
      end

      rule.strip!
      nft[table][chain].push(rule)
    end

  end

  nft
end

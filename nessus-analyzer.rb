#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'
require 'terminal-table'

report_root_dir = "/data/nessus-analyzer-data/"
aggregate_high_severity_count = 0 
hosts_with_high_severity_count = 0
total_hosts = 0

Dir.glob(report_root_dir+'*.nessus') do |report_file|
  Nessus::Parse.new(report_file) do |scan|
    aggregate_high_severity_count += scan.high_severity_count
    total_hosts += scan.host_count
    output_table = Terminal::Table.new :title => scan.title
    output_table << ['High severity issues', scan.high_severity_count]
    output_table << ['Medium severity issues', scan.medium_severity_count]
    output_table << ['Low severity isseus', scan.low_severity_count]
    output_table << ['Open ports', scan.open_ports_count]
    puts output_table
    scan.each_host do |host|
      hosts_with_high_severity_count += 1 if host.high_severity_count > 0
    end
  end
end

aggregate_table = Terminal::Table.new :title => "Aggregate statistics"
aggregate_table << ['Aggregate high severity issuse',
                    aggregate_high_severity_count]
aggregate_table << ['Hosts with high severity issues',
                    hosts_with_high_severity_count]
aggregate_table << ['Total hosts',
                    total_hosts]
aggregate_table << ['% hosts with a high severity issue',
                    100 * hosts_with_high_severity_count.to_f / total_hosts]
puts aggregate_table


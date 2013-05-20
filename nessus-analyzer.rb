#!/usr/bin/env ruby

$LOAD_PATH << 'lib'
require 'rubygems'
require 'ruby-nessus'
require 'terminal-table'
require 'yaml'
require 'trollop'

report_root_dir = "/data/nessus-analyzer-data/"

def calculate_top_events(scan, event_count = 10)
  # We're going to store the event details as a hash of hashes
  unique_events = Hash.new{|h, k| h[k] = {}}
  scan.each_host do |host|
    next if host.total_event_count.zero?
    host.each_event do |event|
      # at this point we don't care about informational
      next if event.informational?

      if unique_events.has_key?(event.id)
        unique_events[event.id][:count] += 1
      else
        unique_events[event.id] = {:count => 1,
                                   :name => event.name, 
                                   :severity => event.severity,
                                   :family => event.family,
                                   :synopsis => event.synopsis,
                                   :description=> event.description,
                                   :solution => event.solution,
                                   :cvss_base_score => event.cvss_base_score,
                                   :cve => event.cve,
                                   :cvss_vector => event.cvss_vector }
      end # if
    end # host.each_event
  end # scan.each_host

  # sort the hash by v[:count] (descending)
  puts unique_events.sort_by{|k, v| -v[:count]}.take(event_count).to_yaml
end


def calculate_statistics(scan)
  aggregate_high_severity_count = 0 
  hosts_with_high_severity_count = 0
  total_hosts = 0
  total_hosts += scan.host_count
  aggregate_high_severity_count += scan.high_severity_count

  output_table = Terminal::Table.new :title => scan.title, 
    :style => {:width =>  60 }
  output_table << ['High severity issues', scan.high_severity_count]
  output_table << ['Medium severity issues', scan.medium_severity_count]
  output_table << ['Low severity isseus', scan.low_severity_count]
  output_table << ['Open ports', scan.open_ports_count]
  output_table.align_column(1, :right)
  puts output_table

  scan.each_host do |host|
    hosts_with_high_severity_count += 1 if host.high_severity_count > 0
  end

  aggregate_statistics = Terminal::Table.new :title => "Aggregate statistics",
    :style => { :width => 60 }
  aggregate_statistics << ['Aggregate high severity issuse',
                           aggregate_high_severity_count]
  aggregate_statistics << ['Hosts with high severity issues',
                           hosts_with_high_severity_count]
  aggregate_statistics << ['Total hosts',
                           total_hosts]
  percent_hosts_high_severity = sprintf "%.2f%%", 
    (100 * hosts_with_high_severity_count.to_f / total_hosts)
  aggregate_statistics << ['% hosts with a high severity issue', 
                           percent_hosts_high_severity]
  aggregate_statistics.align_column(1, :right)
  puts aggregate_statistics
end

if __FILE__ == $PROGRAM_NAME

  Dir.glob(report_root_dir+'*.nessus') do |report_file|
    Nessus::Parse.new(report_file) do |scan|
      calculate_top_events(scan, 10)
      # calculate_statistics(scan)
    end
  end
end




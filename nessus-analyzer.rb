#!/usr/bin/env ruby

$LOAD_PATH << 'lib'
require 'rubygems'
require 'ruby-nessus'
require 'terminal-table'
require 'json'
require 'set'
require 'trollop'

def calculate_top_events(scan, event_count)
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
                                   :severity_in_words => event.severity.in_words,
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
  puts unique_events.sort_by{|k, v| -v[:count]}.take(event_count).to_json
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
def find_hosts_by_id(scan, event_id)
  hosts = Set.new 
  scan.each_host do |host|
    next if host.total_event_count.zero?
    host.each_event do |event|
      hosts << host.ip if event.id == event_id
    end
  end
  hosts.to_a
end

def process_nessus_file(nessus_file)
  Nessus::Parse.new(nessus_file) do |scan|
    calculate_top_events(scan, @opts[:top_events]) unless 
      @opts[:top_events].nil? ||  @opts[:top_events] == 0
    calculate_statistics(scan) if @opts[:show_statistics]
    puts find_hosts_by_id(scan, @opts[:event_id]) if @opts[:event_id]
  end
end

# main
if __FILE__ == $PROGRAM_NAME
  @opts = Trollop::options do
    banner <<-EOS
    Nessus-Analyzer parses nessus output files.
    Usage:
      ./nessus-analyzer.rb [options] [file/directory]
    where [options] are:
    EOS

    opt :top_events, "The <i> most common events", :type => Integer, 
      :short => "-t"
    opt :show_statistics, "Show report statistic", :short => "-s"
    opt :file, "The .nessus file you want to process", :type => String, 
      :short => "-f"
    opt :dir, "The directory containing .nessus files you want to process", 
      :type => String, :short => "-d"
    opt :event_id, "Show all hosts that match the supplied id", 
      :type => Integer, :short => "-e"
  end

  Trollop::die :file, "must exist" unless 
    File.exist?(@opts[:file]) if @opts[:file] 
  Trollop::die :dir, "Your directory must exist" unless 
    Dir.exist?(@opts[:dir]) if @opts[:dir] 
  Trollop::die :dir, "You can't specify a file and directory" if 
    @opts[:file] && @opts[:dir]
  Trollop::die :file, "You need to specify a file or directory" if 
    @opts[:file].nil? && @opts[:dir].nil?

  if @opts[:dir]
    path = @opts[:dir].dup
    path << '/' if path[-1] != '/' # end in a slash
    Dir.glob(path+'*.nessus') do |report_file|
      process_nessus_file report_file
    end
  elsif @opts[:file]
    report_file = @opts[:file]  
    process_nessus_file report_file
  end
end

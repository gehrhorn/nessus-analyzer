#!/usr/bin/env ruby

$LOAD_PATH << 'lib'
require 'rubygems'
require 'ruby-nessus'
require 'terminal-table'
require 'json'
require 'set'
require 'trollop'

def calculate_top_events(scan, event_count)
  # Calculate the top event_count events from scan.
  # Returns json output.

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
  # Calculate statistics and return a pretty table.
  # Probably will refactor this to calc stats as separate functions so they
  # can be sent to graphite / HUD.

  hosts_with_high_severity_issue = 0
  total_hosts = 0
  total_hosts += scan.host_count

  aggregate_cvss_score = 0
  aggreagte_ports = 0
  output_table = Terminal::Table.new :title => scan.title, 
    :style => {:width =>  60 }
  output_table << ['Total hosts', total_hosts]
  output_table << ['High severity issues', scan.high_severity_count]
  output_table << ['Medium severity issues', scan.medium_severity_count]
  output_table << ['Low severity isseus', scan.low_severity_count]
  output_table << ['Open ports', scan.open_ports_count]

  scan.each_host do |host|
    hosts_with_high_severity_issue += 1 if host.high_severity_count > 0

    # host.ports always includes port 0, which I'm not interested in 
    # so I decrement by one
    aggreagte_ports += host.ports.include?("0") ? 
      host.ports.length - 1 : host.ports.length
    host.each_event do |event|
      aggregate_cvss_score += event.cvss_base_score unless 
        event.cvss_base_score == false
    end
  end

  ports_per_host = sprintf "%.2f", ( aggreagte_ports / scan.host_count )
  output_table << ['Ports per host', ports_per_host]
  output_table.add_separator
  output_table << ['Hosts with at least one high severity issue',
                           hosts_with_high_severity_issue]
  percent_hosts_high_severity = sprintf "%.2f%%", 
    (100 * hosts_with_high_severity_issue.to_f / total_hosts)
  output_table << ['% hosts with a high severity issue', 
                           percent_hosts_high_severity]

  output_table.align_column(1, :right)
  output_table
end

def find_hosts_by_id(scan, event_id)
  # return an array of all hosts IPs that contain a certain event_id
  # Use a set to prevent duplicates
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
  # deal with nessus_file per the Trollop opts that were set
  Nessus::Parse.new(nessus_file) do |scan|
    calculate_top_events(scan, @opts[:top_events]) unless 
      @opts[:top_events].nil? ||  @opts[:top_events] == 0
    puts calculate_statistics(scan) if @opts[:show_statistics]
    puts find_hosts_by_id(scan, @opts[:event_id]) if @opts[:event_id]
  end
end

# main
if __FILE__ == $PROGRAM_NAME
  # determine options and call a file or dir.glob a list of files
  # to the block
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

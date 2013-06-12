#!/usr/bin/env ruby

$LOAD_PATH << 'lib'
require 'rubygems'
require 'nessus'
require 'terminal-table'
require 'yaml'
require 'json'
require 'set'
require 'trollop'
require 'socket'
require 'pp'

def calculate_top_events(scan, event_count)
  # Calculate the top event_count events from scan.
  # Returns yaml output.

  # We're going to store the event details as a hash of hashes
  unique_events = Hash.new{|h, k| h[k] = {}}
  scan.each_host do |host|
    next if host.total_event_count.zero?
    host.each_event do |event|
      # at this point we don't care about informational
      next if event.informational?

      # if the key exists increment the :count value by one
      # otherwise create it and set the :count value to one
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

  # sort the hash by v[:count] (descending) and then take event_count items
  unique_events.sort_by{|k, v| -v[:count]}.take(event_count).to_yaml

end

def display_stats_table(scan, cvss_per_host, ports_per_host, high_severity_hosts, events_per_host)

  output_table = Terminal::Table.new :title => scan.title, 
    :style => {:width =>  60 }
  output_table << ['Total hosts', scan.host_count]
  output_table << ['High severity issues', scan.high_severity_count]
  output_table << ['Medium severity issues', scan.medium_severity_count]
  output_table << ['Low severity isseus', scan.low_severity_count]

  output_table.add_separator
  
  output_table << ['CVSS / host', sprintf("%.2f", cvss_per_host)]
  output_table << ['Ports / host', sprintf("%.2f", ports_per_host)]
  output_table << ['% Hosts with a high severity issue', 
    sprintf("%.2f%%", high_severity_hosts)]
  output_table << ['Events per host', sprintf("%.2f", events_per_host)]
  output_table.align_column(1, :right)
  output_table 

end

def send_graphite_stats(cvss_per_host, ports_per_host, high_severity_hosts, events_per_host)
  unless @opts[:timestamp]
    # if :timestamp isn't defined we'll use the most recent midnight
    now = Time.new
    @opts[:timestamp] = Time.new(now.year, now.month, now.day, 0,0,0).to_i
  end
  
  begin 
    graphite_socket = TCPSocket.open(@opts[:graphite_server], 2003)
  rescue
    # write the error message if we can't open the socket
    puts "Died with #{$!}"
    exit
  else
    # write to graphite here
    graphite_socket.write("#{@opts[:graphite_metric]}.cvssperhost #{cvss_per_host} #{@opts[:timestamp]}\n")
    graphite_socket.write("#{@opts[:graphite_metric]}.portsperhost #{ports_per_host} #{@opts[:timestamp]}\n")
    graphite_socket.write("#{@opts[:graphite_metric]}.highseverityhosts #{high_severity_hosts} #{@opts[:timestamp]}\n")
    graphite_socket.write("#{@opts[:graphite_metric]}.eventsperhost #{events_per_host} #{@opts[:timestamp]}\n")
    graphite_socket.close
  end
end

def calculate_statistics(scan)
  # calculate some stats. 
  aggregate_cvss_score = 0
  aggregate_ports = 0
  high_severity_hosts = 0
  aggregate_event_count = 0
  scan.each_host do |host|
    host.each_event do |event| 
      aggregate_cvss_score += event.cvss_base_score unless
        event.cvss_base_score == false
    end

    host.ports.delete("0")
    aggregate_ports += host.ports.length

    high_severity_hosts += 1 if host.high_severity_count > 0
    aggregate_event_count += host.event_count
  end
   
  puts display_stats_table(scan, 
                           aggregate_cvss_score / scan.host_count,
                           aggregate_ports / scan.host_count,
                           100 * ( high_severity_hosts.to_f / scan.host_count ),
                          aggregate_event_count / scan.host_count.to_f)
  
  send_graphite_stats(aggregate_cvss_score / scan.host_count,
                      aggregate_ports / scan.host_count,
                      100 * ( high_severity_hosts.to_f / scan.host_count ),
                      aggregate_event_count / scan.host_count.to_f) if @opts[:graphite_server]
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

def make_mongo_doc(scan)
  scan_results = Array.new
  scan.each_host do |host|
    host_details = Hash.new
    host_details[:ip] = host.to_s
    host_details[:hostname] = host.hostname
    host_details[:mac_addr] = host.mac_addr
    host_details[:os_name] = host.os_name
    host_details[:open_ports] = host.open_ports
    host_details[:event_count] = host.event_count
    host_details[:events] = Array.new
    host.each_event do |event|
      event_details = Hash.new
      event_details[:severity] = event.severity
      event_details[:plugin_id] = event.plugin_id
      event_details[:port] = event.port
      event_details[:family] = event.family
      event_details[:plugin_name] = event.plugin_name
      event_details[:description] = event.description
      event_details[:risk] = event.risk
      event_details[:output] = event.output
      event_details[:patch_publication_date] = event.patch_publication_date.to_s
      event_details[:cvss_base_score] = event.cvss_base_score
      event_details[:cve] = event.cve
      event_details[:cvss_vector] = event.cvss_vector
      host_details[:events] << event_details
    end
    scan_results << host_details
    File.open("#{host.to_s}.out", 'w') { |file| file.write(host_details) }
    pp host_details
  end
  scan_results
  nil
end

def process_nessus_file(nessus_file)
  # deal with nessus_file per the Trollop opts that were set
  Nessus::Parse.new(nessus_file) do |scan|
    puts calculate_top_events(scan, @opts[:top_events]) unless 
      @opts[:top_events].nil? ||  @opts[:top_events] == 0
    puts calculate_statistics(scan) if @opts[:show_statistics]
    puts find_hosts_by_id(scan, @opts[:event_id]) if @opts[:event_id]
    pp make_mongo_doc(scan) if @opts[:mongo]
  end
end

# main
if __FILE__ == $PROGRAM_NAME
  # determine options and call a file or dir.glob a list of files
  # to the block
  @opts = Trollop::options do
    banner <<-EOS
    Nessus-Analyzer parses nessus output files.
    Usage: ./nessus-analyzer.rb [options] -f file
    where [options] are:
    EOS

    opt :file, "The .nessus file you want to process", :type => String, 
      :short => "-f"
    opt :top_events, "The <i> most common events", :type => Integer, 
      :short => "-n"
    opt :show_statistics, "Show report statistic", :short => "-s"
    opt :event_id, "Show all hosts that match the supplied id", 
      :type => Integer, :short => "-e"
    opt :graphite_server, "The graphite server you want to send data to",
      :type => String, :short  => "-g"
    opt :graphite_metric, "The root graphite metric (e.g. stats.security.prodweb, stats.security.cit) you want to send data to",
      :type => String, :short  => "-m"
    opt :timestamp, "Graphite timestamp, defaults midnight of the current date. Be careful you don't nuke your graph.",
      :type  => Integer, :short => "-t"
    opt :mongo, "Turn a scan into a MongoDB document", :short => "-d"
  end

  # Error handling. You have to spicify an action (stats, top x, etc.)
  # and you have to set a file or directory (not both) to process
  Trollop::die :file, 
    "required argument" unless @opts[:file]
  Trollop::die :file, 
    "must exist" unless 
    File.exist?(@opts[:file]) if @opts[:file] 
  Trollop::die :graphite_server, 
    "You need to use --show-statistics or -s if you're sending data to graphite" if
    @opts[:graphite_server] && !@opts[:show_statistics]
  Trollop::die :graphite_server, 
    "You need to specify a metric (-m) to send to graphite" if
    @opts[:graphite_metric].nil? && @opts[:graphite_server]

  process_nessus_file @opts[:file] 
end

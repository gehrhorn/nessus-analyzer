#!/usr/bin/env ruby

$LOAD_PATH << 'lib'
require 'rubygems'
require 'nessus'
require 'terminal-table'
require 'bson'
require 'mongo'
require 'yaml'
require 'trollop'
require 'socket'

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
  # Formats a nice looking table for terminal display
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
    @opts[:timestamp] = Time.local(now.year, now.month, now.day, 0,0,0).to_i
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

def get_aggregate_cvss(host)
  # aggregate_cvss_score is a proxy measure of risk
  aggregate_cvss_score = 0
  host.each_event do |event|
    aggregate_cvss_score += event.cvss_base_score unless
      event.cvss_base_score == false
  end

  aggregate_cvss_score
end

def calculate_statistics(scan)
  # Calculate statistics of interest for metrics.
  # 1. Average aggrergate CVSS per host
  # 2. Average # of open ports per host
  # 3. Percentage of hosts with a high severity event
  # 4. Average number of events per host
  # Other stats (e.g. number of high severity issues) are sent to 
  # send_graphite_stats and display_stats_table via the "scan" parameter
  aggregate_cvss_score = 0
  aggregate_ports = 0
  high_severity_hosts = 0
  aggregate_event_count = 0

  scan.each_host do |host|
    aggregate_cvss_score += get_aggregate_cvss host

    host.ports.delete("0")
    aggregate_ports += host.ports.length

    high_severity_hosts += 1 if host.high_severity_count > 0
    aggregate_event_count += host.event_count
  end
   
  send_graphite_stats(aggregate_cvss_score / scan.host_count,
                      aggregate_ports / scan.host_count,
                      100 * ( high_severity_hosts.to_f / scan.host_count ),
                      aggregate_event_count / scan.host_count.to_f) if @opts[:graphite_server]

  puts display_stats_table(scan, 
                      aggregate_cvss_score / scan.host_count,
                      aggregate_ports / scan.host_count,
                      100 * ( high_severity_hosts.to_f / scan.host_count ),
                      aggregate_event_count / scan.host_count.to_f) if @opts[:show_statistics]
end

def read_config
  begin
    config = YAML.load_file("config.yaml")
    raise "Can't find the #{@opts[:mongo]} section in config.yaml" if 
    config[@opts[:mongo]].nil?
    server = config[@opts[:mongo]]["server"]
    port = config[@opts[:mongo]]["port"]
    database = config[@opts[:mongo]]["database"]
    collection = config[@opts[:mongo]]["collection"]
  rescue
    puts $!
    exit
  else
    return server, port, database, collection
  end
end

def make_mongo_doc(scan)
  # uses the mongo-ruby-driver
  # See: https://github.com/mongodb/mongo-ruby-driver/wiki

  include Mongo
  server, port, database, collection = read_config()

  begin
    dbclient = MongoClient.new(server, port)
  rescue
    puts $!
    exit
  else
    db = dbclient.db(database)
    coll= db[collection]

    #this is for debugging. It deletes the whole collection every time
    # coll.remove
    
    scan.each_host do |host|
      host_details = Hash.new
      host_details["ip"] = host.to_s
      host_details["hostname"] = host.hostname
      host_details["mac_addr"] = host.mac_addr
      host_details["os_name"] = host.os_name
      host_details["open_ports"] = host.open_ports
      host_details["scan title"] = scan.title
      host_details["aggregate_cvss_score"] = get_aggregate_cvss(host)
      host_details["tags"] = @opts[:tags].split(",") unless @opts[:tags].nil?

      # MongoDB BSON driver needs a UTC Time object
      date = host.start_time
      time = Time.utc(date.year, date.month, date.day)
      host_details["scanned_on"] = time

      # All of the nessus 'events' are added to an array called 'events'
      # These are represented as Mongo subdocuments
      # http://docs.mongodb.org/manual/tutorial/model-embedded-one-to-many-relationships-between-documents/

      host_details["events"] = Array.new
      host.each_event do |event|
        event_details = Hash.new
        event_details["plugin_id"] = event.plugin_id
        event_details["severity"] = event.severity
        event_details["plugin_id"] = event.plugin_id
        event_details["port"] = event.port.number.to_s
        event_details["family"] = event.family
        event_details["plugin_name"] = event.plugin_name
        event_details["description"] = event.description
        event_details["risk"] = event.risk
        event_details["output"] = event.output
        event_details["patch_publication_date"] = event.patch_publication_date.to_s
        event_details["cvss_base_score"] = event.cvss_base_score
        event_details["cve"] = event.cve
        event_details["cvss_vector"] = event.cvss_vector
        host_details["events"] << event_details
      end
      id = coll.insert(host_details)
    end

  ensure
    dbclient.close
  end


end

def process_nessus_file(nessus_file)
  # deal with nessus_file per the Trollop opts that were set
  Nessus::Parse.new(nessus_file) do |scan|

    puts calculate_top_events(scan, @opts[:top_events]) unless 
      @opts[:top_events].nil? ||  @opts[:top_events] == 0

    # calculate statistic is used by show_statistics and graphite_server flags
    # for show_statistics it calcs the stats and displays a table
    # for graphite_server it calcs the stats and sends them to graphite
    # if both are specified it does both
    calculate_statistics(scan) if @opts[:show_statistics] || @opts[:graphite_server]

    make_mongo_doc(scan) if @opts[:mongo]
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
      :short => "-e"
    opt :show_statistics, "Show report statistic", :short => "-s"

    opt :graphite_server, "The graphite server you want to send data to",
      :type => String, :short  => "-g"
    opt :graphite_metric, "The root graphite metric (e.g. stats.security.prodweb, stats.security.cit) you want to send data to",
      :type => String, :short  => "-m"
    opt :timestamp, "Graphite timestamp, defaults midnight of the current date. Be careful you don't nuke your graph.",
      :type  => Integer, :short => "-n"

    opt :mongo, "The MongoDB you want to connect to (defined in config.yaml)", 
      :short => "-d", :type  => String
    opt :tags, "Tag Mongo document (provide a comma delimited list, no spaces)",
      :short  => "-t", :type => String
  end

  # File error handling
  Trollop::die :file, 
    "required argument" unless @opts[:file]
  Trollop::die :file, 
    "must exist" unless 
    File.exist?(@opts[:file]) if @opts[:file] 

  # Graphite error handling
  Trollop::die :graphite_server, 
    "You need to specify a metric (-m) to send to graphite" if
    @opts[:graphite_metric].nil? && @opts[:graphite_server]

  # Mongo error handling
  Trollop::die :mongo,
    "Couldn't find config.yaml (start with config.yaml.example)" unless
    File.exist?("config.yaml") if @opts[:mongo]
  Trollop::die :tags,
    "You need to send data to MongoDB to use categories" if @opts[:tags] and @opts[:mongo].nil?

  process_nessus_file @opts[:file] 
end

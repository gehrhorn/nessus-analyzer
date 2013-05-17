#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'

report_root_dir = "/data/nessus-analyzer-data/"
aggregate_high_severity_count = 0 
hosts_with_high_severity_count = 0
total_hosts = 0

Dir.glob(report_root_dir+'*.nessus') do |report_file|
  Nessus::Parse.new(report_file) do |scan|
    aggregate_high_severity_count += scan.high_severity_count
    total_hosts += scan.host_count
    printf "--------------------------------------------------------------\n"
    puts "#{scan.title} included #{ scan.hosts.count } hosts"
    printf "High severity issues: %10d\n", scan.high_severity_count
    printf "Medium severity issues: %8d\n", scan.medium_severity_count
    printf "Low severity issues: %11d\n", scan.low_severity_count
    printf "Total open ports: %14d\n", scan.open_ports_count
    scan.each_host do |host|
      hosts_with_high_severity_count += 1 if host.high_severity_count > 0
    end
    printf "--------------------------------------------------------------\n"
  end
end

printf "Total high severity issues: %3d\n", aggregate_high_severity_count
printf "Total hosts with high severity issues: %d\n", 
  hosts_with_high_severity_count
printf "Total hosts: %d\n", total_hosts
printf "%% hosts with a high severity issue: %.2f", 
  100 * hosts_with_high_severity_count.to_f / total_hosts.to_f

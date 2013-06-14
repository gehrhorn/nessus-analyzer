# Tool to analyze Nessus output

## Running the analyzer
Every time you run the analyzer you need to supply two options:

1. The file or you want to analyze.
2. The action you want to take (find top events, show stats, send to graphite, etc)

```
Usage: ./nessus-analyzer.rb [options] -f report.nessus 
  where [options] are:
  --file, -f <s>:   The .nessus file you want to process
  --top-events, -n <i>:   The <i> most common events
  --show-statistics, -s:   Show report statistic
  --graphite-server, -g <s>:   The graphite server you want to send data to
  --graphite-metric, -m <s>:   The root graphite metric to send data to
  --timestamp, -t <i>:   Graphite timestamp, defaults midnight of the current date.
  --mongo, -d: Turn a file into a document that can be imported into mongo
  --help, -h:   Show this message
```

## Examples
### Sending data to MongoDB
Nessus-analyzer supports sending data to MongoDB. To do this you need to 
configure your config.yaml file.

```yaml
development:
  server:     devmongo
  port:       27017
  database:   nessus
  collection: scans

production:
  server:     mongo
  port:       27017
  database:   nessus
  collection: scans
```

To send data to mongo you need to spucify the database ```--mongo development```
and (optionally) tag your scan.

```./nessus-analyzer -f report.nessus -d development -t web,dev,Linux```


The above sends data to the development database and tags each host in that 
scan with: web, dev, and Linux. Tags are useful to query on later. Tags are 
optional. 

```./Nessus-analyzer -f report.nessus -d development```

This sends the same report to the development database, but omits any tags.


### Displaying scan statistics
``` 
 ./nessus-analyzer.rb -f report.nessus -s
 +------------------------------------------+---------------+
 |                   SCAN TITLE GOES HERE                   |
 +------------------------------------------+---------------+
 | Total hosts                              |           826 |
 | High severity issues                     |          1547 |
 | Medium severity issues                   |          7475 |
 | Low severity isseus                      |          1576 |
 +------------------------------------------+---------------+
 | CVSS / host                              |         58.67 |
 | Ports / host                             |         12.00 |
 | % Hosts with a high severity issue       |        88.01% |
 | Events per host                          |         12.83 |
 +------------------------------------------+---------------+
```
### Running stats and sending them to [ Graphite ](http://graphite.wikidot.com/)
```
./nessus-analyzer.rb -f report.nessus -s -g devgraphite -m stats.security.prodweb
```

## Dependencies
* [ ruby-nessus ](https://github.com/mephux/ruby-nessus)
* [mongo-ruby-driver](https://github.com/mongodb/mongo-ruby-driver)
* [terminal-table](https://github.com/visionmedia/terminal-table)
* [bson_ext](https://rubygems.org/gems/bson_ext) - *not actually required, but significant perfornamce penalties witout it.*

## Conrtibuting
* Fork the project. Generally I think [Scott Chacon]
(http://scottchacon.com/2011/08/31/github-flow.html) offers good advice on the
subject.
* Make a topic branch.
* Squash your commits.
* Add tests for it. This is important so I don't break it in a
  future version unintentionally. (I realize there are no tests now, the irony
  isn't lost on me).
* Don't edit the version, tags, or history.
* Send me a pull request. 

:beers:

# Tool to analyze Nessus output

## Running the analyzer
Every time you run the analyzer you need to supply two options:

1. The file or you want to analyze.
2. The action you want to take (find top events, show stats, send to graphite, etc)

## Features
* [Send data to MongoDB](https://github.com/gehrhorn/nessus-analyzer/wiki/MongoDB) to maintain a historical view of vulnerability data.
* [Send data to Graphite](https://github.com/gehrhorn/nessus-analyzer/wiki/Graphite) to build a vulnerability dashboard.
* [Print some pretty statistics](https://github.com/gehrhorn/nessus-analyzer/wiki/Display-Statistics)

## Dependencies
* [ruby-nessus](https://github.com/mephux/ruby-nessus)
* [mongo-ruby-driver](https://github.com/mongodb/mongo-ruby-driver)
* [terminal-table](https://github.com/visionmedia/terminal-table)
* [bson_ext](https://rubygems.org/gems/bson_ext) - *not actually required, but significant perfornamce penalties witout it.*

## Contributing
* I would love your help. Features, tests, documentation, bug reporting, etc.
Really, I would love it.
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

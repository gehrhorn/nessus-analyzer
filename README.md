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

## Documentation
The [wiki](https://github.com/gehrhorn/nessus-analyzer/wiki) has more information.

## Contributing
Want to [help](https://github.com/gehrhorn/nessus-analyzer#contributing)? I'd really love it.
* [Submit](https://github.com/gehrhorn/nessus-analyzer/issues) a bug
* [Edit](https://github.com/gehrhorn/nessus-analyzer/wiki/_pages) the wiki
* Improve the [documentation](https://github.com/gehrhorn/nessus-analyzer/blob/master/README.md)
* Write some tests
* [Fork](https://github.com/gehrhorn/nessus-analyzer/fork) the project and add new features

:beers:

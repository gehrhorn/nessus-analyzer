# Tool to analyze Nessus output

Make sure you have [ruby-nessus](https://github.com/mephux/ruby-nessus) installed from [source](https://github.com/mephux/ruby-nessus) or via a [gem](http://rubygems.org/gems/ruby-nessus). You can include ruby-nessus with:

```
require 'nessus'
```

## Running the analyzer
Every time you run the analyzer you need to supply two options:

1. The file or directory of files that you want to analyze (never both).
2. The action you want to take (find top events, show stats, send to graphite, etc)

```
Options:
    --top-events, -t <i>:   The <i> most common events
    --show-statistics, -s:   Show report statistic
    --file, -f <s>:   The .nessus file you want to process
    --dir, -d <s>:   The directory containing .nessus files you want to process
    --event-id, -e <i>:   Show all hosts that match the supplied id
    --help, -h:   Show this message
```
:beers:

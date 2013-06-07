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
    Nessus-Analyzer parses nessus output files.
      Usage: ./nessus-analyzer.rb [options] [file/directory]
        where [options] are:
        --top-events, -n <i>:   The <i> most common events
        --show-statistics, -s:   Show report statistic
        --file, -f <s>:   The .nessus file you want to process
        --dir, -d <s>:   The directory containing .nessus files you want to process
        --event-id, -e <i>:   Show all hosts that match the supplied id
        --graphite-server, -g <s>:   The graphite server you want to send data to
        --graphite-metric, -m <s>:   The root graphite metric (e.g. stats.security.prodweb, stats.security.cit) you want to send data to
        --timestamp, -t <i>:   Graphite timestamp, defaults midnight of the current date. Be careful you don't nuke your graph.
        --help, -h:   Show this message
```

## Examples
### Running statistics of one scan
``` 
 ./nessus-analyzer.rb -f /data/nessus-analyzer-data/report.nessus -s
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
### Running statistics of an entire directory
```
./nessus-analyzer.rb -d /data/nessus-analyzer-data -s
+------------------------------------------+---------------+
|                   SCAN TITLE GOES HERE                   |
+------------------------------------------+---------------+
| Total hosts                              |           122 |
| High severity issues                     |           271 |
| Medium severity issues                   |          1125 |
| Low severity isseus                      |           201 |
+------------------------------------------+---------------+
| CVSS / host                              |         58.05 |
| Ports / host                             |         15.00 |
| % Hosts with a high severity issue       |        82.79% |
| Events per host                          |         13.09 |
+------------------------------------------+---------------+

+-------------------------------------------+--------------+
|                   SCAN TITLE GOES HERE                   |
+-------------------------------------------+--------------+
| Total hosts                               |            1 |
| High severity issues                      |            0 |
| Medium severity issues                    |            5 |
| Low severity isseus                       |            0 |
+-------------------------------------------+--------------+
| CVSS / host                               |        50.00 |
| Ports / host                              |         1.00 |
| % Hosts with a high severity issue        |        0.00% |
| Events per host                           |         5.00 |
+-------------------------------------------+--------------+
```
### Running stats and sending them to graphite
```
./nessus-analyzer.rb -f /data/nessus-analyzer-data/report_10s.nessus -s -g devgraphite -m stats.security.prodweb
```
### Getting the top 5 events in a scan
```yaml
./nessus-analyzer.rb -f /data/nessus-analyzer-data/report.nessus -n 5
- - 33929
  - :count: 945
  :name: PCI DSS compliance
  :severity: 3
  :severity_in_words: High Severity
  :family: Policy Compliance
  :synopsis: Nessus has determined that this host is NOT COMPLIANT with the PCI
  DSS requirements.
  :description: ! 'The remote web server is vulnerable to cross-site scripting (XSS)
  attacks, implements old SSL2.0 cryptography, runs obsolete software, or is affected
  by dangerous vulnerabilities (CVSS base score >= 4).


  If you are conducting this scan through the Nessus Perimeter Service Plugin,
  and if you disagree with the results, you may submit this report by clicking
  on ''Submit for PCI Validation'' and dispute the findings through our web interface.'
  :solution: false
  :cvss_base_score: false
  :cve: false
  :cvss_vector: false
- - 65821
   - :count: 595
   :name: SSL RC4 Cipher Suites Supported
   :severity: 1
   :severity_in_words: Low Severity
   :family: General
   :synopsis: The remote service supports the use of the RC4 cipher.
   :description: ! "The remote host supports the use of RC4 in one or more cipher
   suites. The RC4 cipher is flawed in its generation of a pseudo-random stream
   of bytes so that a wide variety of small biases are introduced into the stream,
   decreasing its randomness. \n\nIf plaintext is repeatedly encrypted (e.g.  HTTP
   cookies), and an attacker is able to obtain many (i.e.  tens of millions) ciphertexts,
   the attacker may be able to derive the plaintext."
   :solution: Reconfigure the affected application, if possible, to avoid use of
   RC4 ciphers.
   :cvss_base_score: 2.6
   :cve: CVE-2013-2566
   :cvss_vector: CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N
...
```
:beers:

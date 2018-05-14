## NAME
isashark - Application for offline analysis of network traffic.

## DESCRIPTION
Console application for offline network analysis of packets saved  
in .pcap files.  Supported are protocols from TCP/IP family.  

## RUN
`./isashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file`   

## OPTIONS
`aggr-key` (optional) aggregation of packets by:  
- `srcmac` source MAC adress  
- `dstmac` destination MAC adress  
- `srcip` source IP adress  
- `dstip` destination IP adress  
- `srcport` source port  
- `dstport` destination port  

`sort-key` (optional) sort packets by:  
- `packets` number of packets  
- `bytes` size of packets  

`limit` (optional) limit the number of listed packets  

`filter-expression` (optional) pcap-filter(7) string  

`file` one or more .pcap files  

## EXAMPLES
* Analysis of all packets in file *file.pcap*  
located in the same directory as *isashark*:  
`./isashark file.pcap`  

* Display help:  
`./isahsark -h`  

* Aggregation of packets by source IP address and sorting  
podľa počtu paketov súboru *file.pcap*:  
`./isashark -a srcip -s packets file.pcap`  

* Analysis of packets in 3 files at once:  
`./isashark file1.pcap file2.pcap file3.pcap`  

* Using *pcap-filter(7)* expression and file *file.pcap*:  
`./isashark -f "port 20" file.pcap`  

* Limit output to 5 packets from file *file.pcap*:  
`./isashark -l 5 file.pcap`  

## LIST OF FILES
- Makefile  
- README.md  
- isashark.cpp  
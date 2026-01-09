# View Captured File Properties

![](Pasted%20image%2020250831065223.png)

# View all Resolved Address

`Statistics -> Resolved Address`

![](Pasted%20image%2020250831065319.png)

# View list of conversations

`Statistics -> Conversations`

![](Pasted%20image%2020250831065417.png)

# View Unique Endpoints

`Statistics -> Endpoints`

![](Pasted%20image%2020250831065538.png)

# Filter

## Capture Filters

`Capture -> Capture Filters`

![](Pasted%20image%2020250831065736.png)

## Display Filters

`Analyze -> Display Filters`

![](Pasted%20image%2020250831065815.png)

## Display all type A DNS

`dns && dns.flags.response == 0 && dns.qry.type == 1`

## HTTP Packets contains Apache

`http.server contains "Apache"`

![](Pasted%20image%2020250831065958.png)

## HTTP Packets host fields match .php or .html

`http.host matches "\.(php|html)"`

## Packets that use port 80,443, or 8080

`tcp.port in {80 443 8080}`

## Packets with Even TTL numbers

`string(ip.ttl) matches "[02468]$"`

## Detect Nmap TCP Connect scans

`tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024`

## UDP Close Port

`icmp.type == 3 and icmp.code == 3`

## UDP port in range 55 - 70

`udp.port in {55 .. 70}`

or

`udp.port >= 55 and udp.port <= 77`

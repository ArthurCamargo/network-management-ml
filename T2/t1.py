from tkinter import *
from tkinter import ttk
from easysnmp import Session
import json
from login import loginPage
import os
import time
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import math
import numpy as np
import pandas as pd
from model.trainer import Classifiers

BANDWIDTH_DELAY = 5000 # Miliseconds

#Starts the main app window
def startRoot():
    root = Tk()
    root.title("SNMPal") #Very very cool name, very punny = very funny
    return root

#Creates a session with an Agent
#The version is hardseted to 3 and the security_level to the highest one
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

#This function creates the window that allows an user to register new agents
def createAgentButtonForm(logged_user):
    agentButtonForm = Toplevel() #new window

    #Adds all entries
    agent_AliasEntry = Entry(agentButtonForm)
    ip_AddrEntry = Entry(agentButtonForm)
    sec_userEntry = Entry(agentButtonForm)
    communityEntry = Entry(agentButtonForm)
    auth_protocolEntry = Entry(agentButtonForm)
    auth_passwordEntry = Entry(agentButtonForm)
    privacy_protocolEntry = Entry(agentButtonForm)
    privacy_passwordEntry = Entry(agentButtonForm)

    #Adds labels 
    agent_AliasLabel = Label(agentButtonForm, text="Agent Alias: ")
    ip_AddrLabel = Label(agentButtonForm, text="Ip Address: ")
    sec_userLabel = Label(agentButtonForm, text="User: ")
    communityLabel = Label(agentButtonForm, text="Community: ")
    auth_protocolLabel = Label(agentButtonForm, text="Auth Protocol: ")
    auth_passwordLabel = Label(agentButtonForm, text="Auth Password")
    privacy_protocolLabel = Label(agentButtonForm, text="Privacy Protocol")
    privacy_passwordLabel = Label(agentButtonForm, text="Privacy Password")

    #places labels and entries on grid
    agent_AliasLabel.grid(row=0, column=0, sticky="E")
    ip_AddrLabel.grid(row=1, column=0, sticky="E")
    sec_userLabel.grid(row=2, column=0, sticky="E")
    communityLabel.grid(row=3, column=0, sticky="E")
    auth_protocolLabel.grid(row=4, column=0, sticky="E")
    auth_passwordLabel.grid(row=5, column=0, sticky="E")
    privacy_protocolLabel.grid(row=6, column=0, sticky="E")
    privacy_passwordLabel.grid(row=7, column=0, sticky="E")

    agent_AliasEntry.grid(row=0, column=1)
    ip_AddrEntry.grid(row=1, column=1)
    sec_userEntry.grid(row=2, column=1)
    communityEntry.grid(row=3, column=1)
    auth_protocolEntry.grid(row=4, column=1)
    auth_passwordEntry.grid(row=5, column=1)
    privacy_protocolEntry.grid(row=6, column=1)
    privacy_passwordEntry.grid(row=7, column=1)

    #this button calls a function that receives all the data from this form and stores in a JSON file for later use
    submitAgentButton = Button(agentButtonForm, text="Create", command=lambda: createAgentJSON(logged_user, agent_AliasEntry.get() ,ip_AddrEntry.get(), sec_userEntry.get(),communityEntry.get(
    ), auth_protocolEntry.get(), auth_passwordEntry.get(), privacy_protocolEntry.get(), privacy_passwordEntry.get(), agentButtonForm))
    submitAgentButton.grid(row=8, column=0)

# Stores all data from a new agent connection to a json file
def createAgentJSON(user_owner, agent_alias, ip_addr, sec_user, community, auth_protocol, auth_password, privacy_protocol, privacy_password, agentButtonForm):
    jsonData = []

    dictionary = {
        "user_owner": user_owner,   #Using the current logged user to verify later ownership
        "agent_alias" : agent_alias,
        "ip_addr": ip_addr,
        "sec_user": sec_user,
        "community": community,
        "auth_protocol": auth_protocol,
        "auth_password": auth_password,
        "privacy_protocol": privacy_protocol,
        "privacy_password": privacy_password
    }



    with open("agents.json", "r") as jsonfile:
        jsonData = json.load(jsonfile)
       # print("Running 1") #Debug stuff

    jsonData.append(dictionary)

    with open("agents.json", "w") as jsonfile:
        json.dump(jsonData, jsonfile, indent=4)
      #  print("Running 2") #Debug stuff

    agentButtonForm.destroy()  #Closes the agent creation form
    return

# This function checks the JSON file with all agent connection data and creates a button for every agent CREATED BY THE CURRENT USER
def loadAgentButtons(logged_user, tab_control):
    open_sessions.clear()
    with open("agents.json", "r") as jsonfile:
        agentsJson = json.load(jsonfile)
    for agent in agentsJson:
        if agent["user_owner"] == logged_user:  
            startSession(agent["ip_addr"],agent["sec_user"],agent["community"], agent["auth_protocol"],agent["auth_password"], agent["privacy_protocol"],agent["privacy_password"])
            agent_tab = Frame(tab_control)
            tab_control.add(agent_tab, text = agent["agent_alias"])

def print_session_info(session_index):
    session = open_sessions[session_index]
    print(f"Printando infos da sessao {session_index}")
    print(session.get("sysName.0").value)

def get_protocol_info(session_index):
    """ Return the protocol  information"""
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
    session = open_sessions[session_index]
    info = {}
    for var in variables:
        value = session.get_next(var).value
        info[var] = value
        print(var, value)
    return info

def createBase(tab_control):
    base = []
    for index, tab in enumerate(tab_control.winfo_children()):
        base.append(get_protocol_info(index))

    return base


def createInfoLabels(tab_control, base, clfs):
    for index, tab in enumerate(tab_control.winfo_children()):
        X = pd.DataFrame([base[index]], dtype='float')
        info = get_protocol_info(index)
        I = pd.DataFrame([info], dtype = 'float')

        print(X.shape)
        print(I.shape)
        frames = [X, I]
        X = pd.concat(frames)
        X = X.diff()
        print("something")
        print(X)

        #destroy all children with violence
        for child in tab.winfo_children():
            child.destroy()

        for col in X.columns:
            ttk.Label(tab,  text = col + " " + str(X[col].iloc[1])).pack()

        print([X.iloc[1]])
        ttk.Label(tab, text = "Decision Tree: "  +  str(clfs.dt.predict([X.iloc[1]]))).pack()

        base[index] = info
    root.after(5000, createInfoLabels, tab_control, base, clfs)



logged_user = loginPage() # Opens the login page and saves the current user after login

print("Logged as " + logged_user) #Debug stuff

global open_sessions #Creates a list of sessions -- Using a global variable because it's easier than trying to get inputs returned to buttons
clfs = Classifiers()
open_sessions = []

root = startRoot()  #Starts main app window


tab_control = ttk.Notebook(root)
loadAgentButtons(logged_user, tab_control)
tab_control.pack(expand=1, fill = 'both')

base = createBase(tab_control)
print(base)
createInfoLabels(tab_control, base, clfs)


root.mainloop()  #Turns on the mainloop of the app

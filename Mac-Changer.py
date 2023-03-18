#!/usr/bin/evn python

import subprocess
import optparse

def get_arguments():
    par=optparse.OptionParser()
    par.add_option("-i","--interface",dest="Interface",help="Jei Interface er Mac Address Change korte hobe oita :")
    par.add_option("-m","--mac",dest="Notun_Mac",help="Notun je Mac dibo?")
    (options,arguments)=par.parse_args()
    if not options.interface:
        par.error("[-] Please akta Interface den, or help er jonno use --help.")
    elif not options.new_mac:
        par.error("[-] Please akta notun Mac address diye try koren or use --help .")
    return options

def change_mac(interface,new_mac):
    print(interface+"[+] Mac change kora hosse "+new_mac+" eita hosse apnar new MAC Address.")
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])

options=get_arguments()
change_mac(options.interface,options.new_mac)
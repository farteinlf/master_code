import sys
import subprocess
from os import getcwd
from threading import Thread, Lock
import time


from .toolexecutor import ToolExecutor


class Hostetd(ToolExecutor):
    
    toolcomm = 'hostapd'

    def __init__(self, loglevel : int):
        """Initializes output attributes and sets filepath

        Parameters
        ----------
        loglevel : int
            Level of logger verbosity
        """        
        super().__init__(loglevel)
        self.lock = Lock()
        self.output = []    # buffer for all unread output
        self.out_log = []   # all output from object init
        self.filepath = f'{getcwd()}/hostapd.conf'
        
    
    def __enter__(self):
        """Runs AP with hostapd 

        Spawns a hostapd process using filepath as configuration file.
        A seperate thread continously saves the process output.
        """        
        self.logger.debug('Launching Evil Twin AP...')

        proc_flags = {
            'stdin': subprocess.PIPE,
            'stdout': subprocess.PIPE,
            'stderr': subprocess.STDOUT,
            'bufsize': 1, 
            'universal_newlines': True
        }
        self.proc = subprocess.Popen([self.toolcomm, self.filepath], **proc_flags)
        self.thread = Thread(target=self._store_output)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(5)   # give hostapd time to initialize
        return self
        
    def __exit__(self, *args):
        """Terminates hostapd process 
        """  
        sys.stdout.flush()
        self.logger.debug('Closing Evil Twin AP...')
        self.proc.terminate()
        self.proc.wait(1)
        
    
    def _store_output(self):
        """Stores output to both output and out_log

        Function is continously run by seperate thread when hostapd
        process is running.
        """        
        for line in self.proc.stdout:
            self.logger.debug(f'{line[:-1]}')
            with self.lock:
                self.out_log.append(line)
                self.output.append(line)
                
    def _get_output(self) -> list:
        """Gets current unread hostapd output

        Returns
        -------
        list
            List of strings
        """        
        with self.lock:
            output, self.output = self.output, []
        return output
    
    
    def create_conf(self, interface : str, essid : str, channel : str | int, pw : str) -> str:
        """Create configuration file for hostapd 

        Parameters
        ----------
        interface : str
            Interface to run the AP from
        essid : str
            ESSID (name) of network
        channel : str | int
            Str or int of channel to run network on
        pw : str
            Network WPA2 password

        Returns
        -------
        str
            Filepath to configuration file
        """        


        confdict = {
            'interface': interface,
            'ssid': essid,
            'hw_mode': 'g',
            'channel': str(channel),
            'macaddr_acl':0,
            'ignore_broadcast_ssid': 0,
            'auth_algs': 1,
            'wpa': 2,
            'wpa_passphrase': pw,
            'wpa_key_mgmt': 'WPA-PSK',
            'rsn_pairwise': 'CCMP',
            'wpa_group_rekey': 86400,
            'ieee80211n': 1,
            'wmm_enabled': 1
        }
        confstr = ''
        for key, val in confdict.items():
            confstr += f'{key}={val}\n'
        
        with open(self.filepath, 'w') as conffile:
            conffile.write(confstr)
        
        return(self.filepath)
    
    def is_client_connected(self, client_bssid : str) -> bool:
        """Checks if client is connected

        Parameters
        ----------
        client_bssid : str
            BSSID of client

        Returns
        -------
        bool
            Returns True if connected. Otherwise False.
        """        

        connected = False
        for line in self.out_log:
            if client_bssid in line.upper():
                if 'AP-STA-CONNECTED' in line:
                    connected = True
                elif 'AP-STA-DISCONNECTED' in line:
                    connected = False
        self.logger.debug(f'Client is connected: {connected}')
        return connected

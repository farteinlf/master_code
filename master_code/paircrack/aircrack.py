from types import NoneType
from .toolexecutor import ToolExecutor
import re

class Aircrack(ToolExecutor):
    """Class that runs aircrack-ng commands

    Capable of performing dictionary attacks against WPA keys, and
    checking if cap files from airodump-ng contains handshake.
    """    
    
    toolcomm = 'aircrack-ng'

    # File containing single pw not likely to be found.
    # Used to check if capfile contains handshake.
    # File must be created before running program.
    # This file should probably be created in a init method.
    testwl = 'testwl.txt' 
    
    def crack_wpa2(self, targetbssid : str, capfile : str, wordlist='/usr/share/set/src/fasttrack/wordlist.txt') -> str | NoneType:
        """Performs dictionary attack against key if in handshake file

        Parameters
        ----------
        targetbssid : str
            BSSID of network access point
        capfile : str
            Filepath to cap file containing handshake packets
        wordlist : str, optional
            Wordlist of potential WPA2 passwords. 
            By default '/usr/share/set/src/fasttrack/wordlist.txt'

        Returns
        -------
        str | NoneType
            Returns password as str, or None object if key is not found
        """        
        
        if not self.check_file_content(capfile): return None
        
        flags = {
            '-w': wordlist,
            '--bssid': targetbssid,
        }
        
        command = self.compound_command([self.toolcomm, capfile, '-q'], flags)
        output = self.run(command).stdout
        if 'KEY FOUND' in output:
            password = re.findall('\[ (.+) \]', output)[0]
            self.logger.debug(f'Key match found: <{password}>')
            return password

        elif 'KEY NOT FOUND' in output:
            self.logger.debug(f'Key not in wordlist ({wordlist})')
            return None

        else:
            self.logger.debug(f'Error during key cracking')
            return None

    
        
    def check_handshake(self, targetbssid : str, capfile : str) -> bool:
        """Checks if cap file contains EAPOL handshake

        Parameters
        ----------
        targetbssid : str
            BSSID of network access point
        capfile : str
            Filepath of cap file 

        Returns
        -------
        bool
            True if handshake is found. False otherwise
        """        
        if not self.check_file_content(capfile): return False
        
        flags = {
            '-w': self.testwl,
            '--bssid': targetbssid,
        }
        command = self.compound_command([self.toolcomm, capfile, '-q'], flags)
        output = self.run(command)
        
        if 'KEY NOT FOUND' in output.stdout:
            self.logger.debug('Handshake discovered in cap file')
            return True
        elif 'Packets contained no EAPOL data' in output.stderr:
            self.logger.debug('Handshake not cap file')
            return False
        else:
            self.logger.debug(f'Recieved error: {output.stderr}')
            return False

import subprocess
from .toolexecutor import ToolExecutor


class Aireplay(ToolExecutor):
    """Class that runs aireplay-ng commands

    Capable of deauthenticating connections between AP and clients.
    """    
    
    toolcomm = 'aireplay-ng'
    
    def deauth(self, interface : str, ap_bssid : str, client_bssid=None) -> subprocess.CompletedProcess:
        """Deauthenticates clients of given AP

        Parameters
        ----------
        interface : str
            Interface to launch deauthentication frames from
        ap_bssid : str
            BSSID of AP
        client_bssid : _type_, optional
            BSSID of client to deauthenticate. If None, all clients
            will be deauthenticated. By default None

        Returns
        -------
        subprocess.CompletedProcess
            The returned output of the subprocess.run function
        """        
        flags = {
            '--deauth': '10',
            '-a': ap_bssid
        }
        if client_bssid is not None:
            flags['-c'] = client_bssid
        
        command = self.compound_command([self.toolcomm, interface], flags)
        output = self.run(command)
        return output
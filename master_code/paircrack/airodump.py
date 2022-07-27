from types import NoneType
from .toolexecutor import ToolExecutor

from os import listdir
import xml.etree.ElementTree as ET


class Airodump(ToolExecutor):
    """Class that runs airodump-ng commands

    Capable of capturing APs, clients of APs and handshakes. Can also
    parse its output files to get APs and clients in a more workable
    format.
    """    
    
    toolcomm = 'airodump-ng'
    
    def capture_aps(self, interface : str, proc_timeout=2) -> str:
        """Captures all access points within range

        Parameters
        ----------
        interface : str
            Interface to capture packets on
        proc_timeout : int, optional
            How long to run the capture, by default 2

        Returns
        -------
        str
            filepath to xml file containing AP data
        """        
        self.logger.debug('Capturing all APs...')
        
        fsuffix = []
        flags = {
            '--write-interval': '1',
            '--output-format': 'netxml'}
        return self._capture(interface, fsuffix, flags, proc_timeout)
        
    def capture_clients(self, interface : str, targetbssid : str, targetchannel : str, proc_timeout=15) -> list:
        """Captures clients and handshake of given access point network

        Parameters
        ----------
        interface : str
            Interface to capture packets on 
        targetbssid : str
            BSSID of access point
        targetchannel : str
            Channel the AP transmits on
        proc_timeout : int, optional
            Amount of seconds to run the capture, by default 15

        Returns
        -------
        list
            list of strings with filepaths where the first is an XML of
            AP and client data, and the second is a cap file of packets
        """        
        self.logger.debug('Capturing specific AP data...')  
        
        fsuffix = ['cap']   
        flags = {
            '--output-format': 'pcap,netxml',
            '--bssid': targetbssid,
            '--channel': targetchannel}
        return self._capture(interface, fsuffix, flags, proc_timeout)
    
    
    def _capture(self, interface : str, fsuffix : list, flags : dict, proc_timeout : int) -> str | list:
        """Private function to support capture_aps and capture_clients

        Parameters
        ----------
        interface : str
            Interface to capture packets on 
        fsuffix : list
            List containing all suffixes of output files
        flags : dict
            Flags or commands to run with the process
        proc_timeout : int
            Amount of seconds the process should run

        Returns
        -------
        str | list
            Returns str of filepath if only one file, otherwise list
        """        
        fsuffix = ['kismet.netxml'] + fsuffix
        fprefix = 'dump'        
        
        flags = {
            '--background': '1',
            '--write': f'{self.folderpath}/{fprefix}',
            **flags}

        command = self.compound_command([self.toolcomm, interface], flags)        
        self.run(command, timeout=proc_timeout)
        
        filenum = sum(filename.startswith(fprefix) and filename.endswith(fsuffix[0]) 
                      for filename in listdir(self.folderpath))
        filepaths = []
        for suffix in fsuffix:
            filepaths.append(f'{self.folderpath}/{fprefix}-{filenum:0>2}.{suffix}')
        
        if len(filepaths) == 1:
            return filepaths[0]
        else:
            return filepaths
    
    
    
    def parse_aps_netxml(self, filepath : str) -> list | NoneType:
        """Parses XML file from airodump-ng to get access point data

        Parameters
        ----------
        filepath : str
            Filepath to XML file

        Returns
        -------
        list | NoneType
            List of tuples where each is an AP in the format (BSSID, 
            ESSID, Channel), or None if file error
        """        
        if not self.check_file_content(filepath):
            self.logger.error('File error')
            return None
        xmlroot = ET.parse(filepath).getroot()
        
        aps = []
        for netw in xmlroot:
            try:
                essid = netw.find('SSID').find('essid').text
                bssid = netw.find('BSSID').text
                channel = netw.find('channel').text
            except AttributeError:
                continue
            else:
                aps.append((bssid, essid, channel))
        return aps
    
    
    def parse_clients_netxml(self, filepath : str, ap_bssid : str) -> list:
        """Parses XML file from airodump-ng to get clients of given AP

        Parameters
        ----------
        filepath : str
            Filepath to XML file
        ap_bssid : str
            BSSID of the AP

        Returns
        -------
        list
            List of BSSIDs of captured clients
        """        
        if not self.check_file_content(filepath):
            self.logger.error('File error')
            return None
        
        xmlroot = ET.parse(filepath).getroot()
        
        clients = []
        for netw in xmlroot:
            if netw.find('BSSID').text == ap_bssid:
                self.logger.debug(f'Parsing clients for {netw.find("SSID").find("essid").text}')
                for client in netw.findall('wireless-client'):
                    clients.append(client.find('client-mac').text)
                break
        return clients
    

        
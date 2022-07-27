import re
from .toolexecutor import ToolExecutor

class Airmon(ToolExecutor): 
    """Class that runs airmon-ng commands

    Capable of identifying interfaces, setting interface to monitor
    mode by running as context manager.
    """    
    
    toolcomm = 'airmon-ng'
    
    def __init__(self, loglevel : int): 
        """Initializes class and sets self.interface 

        Parameters
        ----------
        loglevel : int
            verbosity of logger
        """        
        super().__init__(loglevel)
        
        # Sets interface to first interface found. This is a
        # simplification that works because the internal NIC has
        # monitor mode on computer from which this was developed.
        self.interface = self.id_interfaces()[0]
        
        self.csv_data = None
        self._channel = None


    def __enter__(self):
        """ Set self.interface to monitor mode 
        
        Also kills interfering processes
        """
        self.run([self.toolcomm, 'check', 'kill'])
        start_args = [self.toolcomm, 'start', self.interface]
        if self._channel is not None:
            start_args.append(self._channel)
        self.run(start_args)
        self.interface = f'{self.interface}mon'
        return self
    
    def __exit__(self, *exc_args):
        """ Set monitor interface back to managed mode 
        
        Also restarts NetworkManager which should set system back to 
        normal
        """
        
        if exc_args:
            if exc_args[0] is not None:
                self.logger.exception(f'Exception occured:')

        self.run([self.toolcomm, 'stop', self.interface])
        self.run(['systemctl', 'restart', 'NetworkManager'])
        self.interface = self.id_interfaces()[0]
        return True
        

    @property
    def channel(self) -> str:
        return self._channel

    @channel.setter
    def channel(self, value):
        self._channel = str(value)


    def id_interfaces(self) -> list:
        """Identifies WLAN interfaces on device

        Returns
        -------
        list
            a list of strings of interface names
        """
        data = self.run([self.toolcomm]).stdout
        data = re.sub(r"[\t]+", '\t', data)
        parsed = []
        for line in data.split('\n'):
            if line:
                for i, col in enumerate(line.split('\t')):
                    if i == 1:
                        parsed.append(col)
        return parsed[1:]
     
        

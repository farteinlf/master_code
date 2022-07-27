import logging
import subprocess
from abc import ABC
from os import stat, path

class ToolExecutor(ABC):
    
    logging.basicConfig(level=logging.DEBUG)
    folderpath = '/home/kali/master/code/airodumps'
    
    
    def __init__(self, loglevel : int):
        """Creates a logging.logger with verbosity based on loglevel

        Loglevel 0 -> Logger in logging.INFO
        Loglevel 1 -> Logger in logging.DEBUG
        Loglevel 2 -> Logger in logging.DEBUG and writes stdout+stderr
            from subprocess

        Parameters
        ----------
        loglevel : int
            verbosity level from 0 to 2
        """        
        
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.verbose = False
        if loglevel == 0:
            self.logger.setLevel(logging.INFO)
        if loglevel >= 1:
            self.logger.setLevel(logging.DEBUG)
        if loglevel >= 2:
            self.verbose = True

        
    
    def run(self, command : list, timeout=None, proc_flags={}) -> subprocess.CompletedProcess:
        """Runs the command using subprocesses

        Parameters
        ----------
        command : list
            list of strings of commands
        timeout : int, optional
            the process will be terminated after timeout seconds, by default None
        proc_flags : dict, optional
            extra flags to run with subproccess, by default {}

        Returns
        -------
        subprocess.CompletedProcess
            object returned when running the process. Is Null if timeout is used
        """            

        if timeout is None:
            proc_flags = {
                'capture_output': True,
                'encoding': 'utf-8',
                **proc_flags
            }
        else:
            proc_flags = {
                'timeout': timeout,
                'stdin': subprocess.PIPE,
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                **proc_flags
            }
            
        self.logger.debug(f'Running command: <{command}>')
        if self.verbose:
            self.logger.debug(f'\tkeywords: <{proc_flags}>')
        
        try: 
            output = subprocess.run(command, **proc_flags)
        except subprocess.TimeoutExpired as e:
            self.logger.debug(f'Process timout')
            return True
        else:
            if self.verbose:
                self.logger.debug(f'Captured stdout: <{output.stdout[:-1]}>')
                self.logger.debug(f'Captured stderr: <{output.stderr}>')
            return output
    

    def compound_command(self, command : str, command_args : list) -> list:
        """Adds command str to front of list command_args

        Parameters
        ----------
        command : str
            str add to front of list
        command_args : list
            list of words to add word in front of

        Returns
        -------
        list
            list of words of final command 
        """        
        for itemtuple in command_args.items():
            for word in itemtuple:
                command.append(word)
        return command
    

    def check_file_content(self, filepath : str) -> bool:
        """Checks if file exists and if contains data

        Parameters
        ----------
        filepath : str
            absolute filepath

        Returns
        -------
        bool
            True if exists and has content, otherwise False
        """        
        if not path.exists(filepath):
            self.logger.debug(f'File <{filepath}> not found')
            return False
        elif stat(filepath).st_size == 0:
            self.logger.debug(f'File <{filepath}> is empty')
            return False
        else:
            return True


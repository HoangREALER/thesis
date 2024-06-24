import asyncio
import time
import sys

from os             import system
from typing         import Callable

from .types         import ExitCode, InjectionType, get_logger
from .environment   import env, stats

def clear(): 
    return system('clear')


"""
    A simple front-end interface for displaying fuzzer statistics
"""
class Simple_menu:

    """
        Initialization point
    """
    def __init__(self, 
                 print_to_file: bool):

        if print_to_file:
            f = open("/tmp/fuzzer_stats", "w+")

            def fwrite(line):
                f.write(line + "\n")
            def frefresh():
                f.truncate(0)
                f.seek(0)

            self.printer = fwrite
            self.printer_refresh = frefresh
            self.printer_flush = f.flush
        else:
            self.printer = print
            self.printer_refresh = clear
            self.printer_flush = sys.stdout.flush

    """
        Run interface
    """
    async def run(self, fuzzer) -> None:
        logger = get_logger(__name__)

        start_time = time.clock_gettime(time.CLOCK_MONOTONIC)

        past_time = start_time
        past_count = 0
        throughput = 0

        while env.shutdown_signal == ExitCode.NONE:

            await asyncio.sleep(0.5)

            self.printer_refresh()
            
            current_time = time.clock_gettime(time.CLOCK_MONOTONIC)

            if (current_time - past_time > 2):
                throughput = (stats.total_requests - past_count) / \
                             (current_time - past_time)

                past_count = stats.total_requests
                past_time = current_time

                logger.info("Total Cov: %0.4f, Throughput: %0.2f", \
                            stats.total_cover_score, throughput)

            self.printer("webFuzz\n-----\n")
            self.printer("Stats\n")

            self.printer('Runtime: {:0.2f} min'.format((current_time - start_time) / 60))
            self.printer('Total Requests: {:d}'.format(stats.total_requests))
            self.printer('Throughput: {:0.2f} requests/s'.format(throughput))
            self.printer('Crawler Pending URLs: {:d}'.format(stats.crawler_pending_urls))
            self.printer('Current Coverage Score: {:0.4f}%'.format(stats.current_node.cover_score))
            self.printer('Total Coverage Score: {:0.4f}%'.format(stats.total_cover_score))
            self.printer('Possible {:s}: {:d}'.format('xss' if env.args.injection_type == InjectionType.XSS else 'SQL Injection', stats.total_vuln))

            self.printer('Executing link: {:s}'.format(stats.current_node.url[:105]))
            self.printer('Response time: {:0.2f} sec'.format(stats.current_node.exec_time))

            if stats.current_node.is_mutated:
                self.printer('State: Fuzzing')
            else:
                self.printer('State: Crawling')

            self.printer_flush()

        print("Shut Down Initiated. Please wait, this may take a few seconds...")

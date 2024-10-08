from lib.core.datatype import AttribDict

# sqlmap paths
paths = AttribDict()

# object to store original command line options
cmdLineOptions = AttribDict()

# object to store merged options (command line, configuration file and default options)
mergedOptions = AttribDict()

# object to share within function and classes command
# line options and settings
conf = AttribDict()

# object to share within function and classes results
kb = AttribDict()

# object with each database management system specific queries
queries = {}

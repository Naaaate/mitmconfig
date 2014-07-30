# Man-In-The-Middle Configurator
Hello! Mitm Configurator is Python 2.7 script called mitmconfig.py used for configuring your system settings for use with [mitmproxy](http://mitmproxy.org). Mitm Configurator is compatible with both Mac and Linux!

Usually, you’d need to manually set your IP tables, IP forwarding and launch two arpspoof processes to set up your system for mitmproxy, but this scripts helps automates the process and drops you right into [mitmproxy](http://mitmproxy.org)! Along the way, you can specify your interface and arguments for mitmproxy. Error checking included on all inputs. Mitmconfig uses termcolor for colorful terminal outputs.

### Requirements
* Python 2.7
* mitmproxy
* arpspoof
* termcolor

Termcolor and mitmproxy can be installed via [Pip](https://pypi.python.org/pypi/pip) like so: `pip install mitmproxy`

### What's New In Version 1.0.3
* Code simplification
* Enhanced welcome message art

### Coming Soon
* Enable More Ports For More Traffic Viewing
* Expand Flexibility
* Windows Support
* Awesome ASCII Art

# Polichombr
Collaborative malware analysis framework

Originally presented at SSTIC 2016 ( www.sstic.org )

# Warning
This is a beta version, use at your own risk!

# Installation
## Prerequisites
On a Ubuntu derivative:
        ``sudo apt-get install -y git virtualenv ruby libffi-dev python-dev graphviz gcc libssl-dev python-pip``

## Initialization
        ./install.sh
        ./utils/db_create.py
        
## Get it up and running
        ./run.py
        
Access it at http://localhost:5000

# virtualenv
We use virtualenv, so don't forget to activate the environment

        source flask/bin/activate

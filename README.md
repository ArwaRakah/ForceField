## ForceField

███████╗░█████╗░██████╗░░█████╗░███████╗███████╗██╗███████╗██╗░░░░░██████╗░
██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝██║░░░░░██╔══██╗
█████╗░░██║░░██║██████╔╝██║░░╚═╝█████╗░░█████╗░░██║█████╗░░██║░░░░░██║░░██║
██╔══╝░░██║░░██║██╔══██╗██║░░██╗██╔══╝░░██╔══╝░░██║██╔══╝░░██║░░░░░██║░░██║
██║░░░░░╚█████╔╝██║░░██║╚█████╔╝███████╗██║░░░░░██║███████╗███████╗██████╔╝
╚═╝░░░░░░╚════╝░╚═╝░░╚═╝░╚════╝░╚══════╝╚═╝░░░░░╚═╝╚══════╝╚══════╝╚═════╝░


ForceFIeld is a command line tool to detect APT presence using network traffic in real time manner.

[+]AUTHORS:
* [+]Fatema Al Jarri
* [+]Arwa Alrakah
* [+]Rawan Al shayib
* [+]Layan Al Ali
* [+]Sara Al Shaieb

## ForceField Logo

![ForceField Logo]([https://github.com/arwar/ForceField/raw/main/logo.png](https://github.com/ArwaRakah/ForceField/blob/main/logo.jpeg?raw=true) "ForceField Logo")

## Installation

```
git clone https://github.com/ArwaRakah/ForceField.git
```
## Dependencies:

ForceFIeld depends on the `bcrypt`, `requests`, `urllib3`, `tqdm`, `mysql-connector-python`, `scapy`, `beautifulsoup4`, `colorama` and `scikit-learn` python modules. 

These dependencies can be installed using the requirements file:

- Installation on Windows:
```
c:\python27\python.exe -m pip install -r requirements.txt
```
- Installation on Linux
```
sudo pip install -r requirements.txt
```
Alternatively, you can install the package and its dependencies using `setup.py`:

- Installation on Windows:
```
python setup.py install
```
- Installation on Linux
```
sudo python setup.py install
```

## Before Running ForceFIeld (For Administrators usage)  
* Make sure to follow the steps in the User Manual: (https://scribehow.com/shared/ForceField_User_Manual__U2ip2-BXRmm4t-v7EsNRBw)
  
## Run ForceFIeld 
```
python ForceField.py
```

## Commands

Short Form    | Long Form     | Description
------------- | ------------- |-------------
-r            | --report      | Generate a report of real-time sniffing
-u            | --upload      | Upload new data and make predictions
-i            | --history     | Display report history
-g            | --register    | Register a new Admin
-c            | --cti         | Display CTI reports
-s            | --sniff       | Start Sniffing
-l            | --logout      | Log out
-h            | --help        | show the help message and exit

### Examples

* To list all the  options and commands use -h switch:

```python ForceField.py -h```

* To start sniffing real-time network traffic use -s switch:

``python ForceField.py -s``

## Credits

* [MITER ATT@CK](https://github.com/TheRook](https://attack.mitre.org/groups/)) - The APT latest TTPs extracted from it **CTI reports**. 


## Version
**Current version is 1.0**

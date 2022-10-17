<!-- Based on the Best-README-Template:
https://github.com/othneildrew/Best-README-Template/blob/master/README.md -->

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <img src="images/logo.png" alt="Logo" width=100>
<p>
<h2 align="center">Amphivena</h2>


<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#os-support">OS Support</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#environment-prep">Environment Prep</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
Amphivena is a Python-based MitM tool for exercising packet manipulation with byte-level precision. MitM scenarios can be configured and executed repeatedly through the use of JSON 'playbooks'.


### OS Support
Amphivena has been built and primarily tested on [Kali](https://www.kali.org/) however it should be compatible with other Debian-based distributions.    
At this time the project is exclusively leveraging [NetfilterQueue](https://github.com/kti/python-netfilterqueue) for packet queueing, and does not support Windows.


### Built With
Primary packages used by Amphivena:
* [Scapy](https://github.com/secdev/scapy) - packet parsing capabilities
* [NetfilterQueue](https://github.com/kti/python-netfilterqueue) - kernel packet capture and forwarding
* [Jsonschema](https://github.com/python-jsonschema/jsonschema) - playbook schema validation

<!-- GETTING STARTED -->
## Getting Started

The following are quick steps to get Amphivena running.

### Prerequisites
```
Python >= 3.9.12
Poetry >= 1.2
```

### Environment Prep
1. Clone the repo
```
git clone https://github.com/ajmassi/Amphivena.git
```
2. Install build dependencies
```
apt install python-dev python3-pip build-essential libnetfilter-queue
```

<!-- USAGE EXAMPLES -->
## Usage
Due to NetfilterQueue hooking in to the kernel packet filter, Amphivena requires root-level permissions to execute.
1. Engage root
```
sudo su
```
2. Install dependencies
```
poetry install
```
3. Start the UI!
```
poetry run python amphivena
```


<!-- LICENSE -->
## License

See `LICENSE` for more information.

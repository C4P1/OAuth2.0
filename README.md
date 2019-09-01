# Item Catalog Project

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Intro](#intro)
- [Installation](#installation)
- [Instructions](#instructions)


## Intro

This readme provides information on the expected and proper functionality of the included python project.


## Installation

This segment goes through all the software and dependencies necessary before the program can be run.

### Install Python Version 3

Python is the programming language the actual code is written in. It needs to be installed on your host machine.
[Download Python 3](https://www.python.org/downloads/) for the host OS using the link. Make sure the version of python is 
1. Above Python 3.0.0
2. Appropriate for your OS

### Install Vagrant

Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem.
[Download it from vagrantup.com.](https://www.vagrantup.com/downloads.html) Install the version for your operating system.

**Windows users:** The Installer may ask you to grant network permissions to Vagrant or make a firewall exception. Be sure to allow this.

### Install VirtualBox

VirtualBox is the software that actually runs the virtual machine.
[You can download it from virtualbox.org, here.](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)
Install the _platform package_ for your operating system. You do not need the extension pack or the SDK.
You do not need to launch VirtualBox yourself. Vagrant will handle that.

**Note:** From the Vagrant website, as of July 2019,
The VirtualBox provider is compatible with VirtualBox versions 4.0.x, 4.1.x, 4.2.x, 4.3.x, 5.0.x, 5.1.x, 5.2.x, and 6.0.x. Other versions are unsupported and the provider will display an error message. Please note that beta and pre-release versions of VirtualBox are not supported and may not be well-behaved.

**Ubuntu users:** If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center instead. Due to a reported bug, installing VirtualBox from the site may uninstall other software you need.

To be safe, it is recommended to download VirtualBox 5.1 from the link above, as it is has been tested and confirmed compatible.

### Download the VM configuration

**Windows:** Use the Git Bash program (installed with Git) to get a Unix-style terminal.  
**Other systems:** Use your favorite terminal program.

Unzip the provided zip file to any directory.

This will give you a directory, complete with the source code for the flask application, a vagrantfile, and a bootstrap.sh file for installing all of the necessary tools. 




## Instructions

### Set up the virtual environment

Install the required software as mentioned above. Restart your PC if asked, then proceed.
1. Move into the **vagrant** directory using the terminal. Then type 'vagrant up' in the terminal. This causes Vagrant to download and install the virtual OS. Feel free to go have a coffee because this could take a while (several minutes).
2. Once the installation finishes and you have control of the terminal again, run 'vagrant ssh' to log in to the new virtual machine.
	If your terminal prompt now starts with the word 'vagrant'. Congratulations, the log in was successful.	
3. Inside the VM, cd to '/vagrant' and ensure that the files present in the VM (use ls) are the same as the ones in your host machines **vagrant** folder.


### Set up the data

1. (Within vagrant itself) Run database_setup.py.
2. (Optional) Once it finishes, run item_database.py to populate the database.


### Run the project

1. In the virtual machine terminal, cd to the correct folder, where the project.py file is placed.
2. Run 'python project.py' to run the program.
3. On a javascript enabled browser (All testing was done on Google Chrome). Go to localhost:5000. From here, please proceed to use the application as you see fit.


### Getting the endpoints

This application provides 3 JSON endpoints. They are:
1. localhost:5000/items/JSON	- To get all items in the database.
2. localhost:5000//category/<int:category_id>/JSON	- To get all items in the database that belong to a specific category.
3. localhost:5000/item/<int:item_id>/JSON	- To get details on one particular item.

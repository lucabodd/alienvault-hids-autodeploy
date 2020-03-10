cp ~/.bashrc  ~/.bashrc.bkp
wget https://raw.githubusercontent.com/lucabodd/Alienvault-hids-autodeploy/master/setup/files/.bashrc -O ~/.bashrc
wget https://github.com/lucabodd/Alienvault-hids-autodeploy/blob/master/setup/files/cluster-delete-agent -O /usr/local/bin/cluster-delete-agent
chmod a+x /usr/local/bin/cluster-delete-agent

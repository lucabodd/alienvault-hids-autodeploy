cd /tmp
wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz
tar -xvf go1.13.3.linux-amd64.tar.gz
mv go /usr/local
echo 'export GOROOT=/usr/local/go' >> ~/.profile
echo 'export GOPATH=$HOME/go/Alienvault-hids-deploy' >> ~/.profile
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.profile
echo "checking go installed version"
go version
echo "Environment settings"
go env
echo "Installing scanner ..."
go get github.com/lucabodd/Alienvault-hids-autodeploy
go install github.com/lucabodd/Alienvault-hids-autodeploy
echo "Done!"

wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz
tar -xvf go1.13.3.linux-amd64.tar.gz
mv go /usr/local
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc
echo "checking go installed version"
go version
echo "Environment settings"
go env
echo "Installing scanner ..."
go get github.com/lucabodd/Alienvault-hids-autodeploy
go install github.com/lucabodd/Alienvault-hids-autodeploy
echo "Done!"
echo "please 'source ~/.bashrc' "

cd /tmp
wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz
tar -xvf go1.13.3.linux-amd64.tar.gz
mv go /usr/local
export GOROOT=/usr/local/go
export GOPATH=$HOME/go/Alienvault-hids-deploy
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
echo "checking go installed version"
go version
echo "Environment settings"
go env

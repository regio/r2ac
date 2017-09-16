#!/bin/bash
server = ''
while true; do
	echo "Choose your option:"
	echo "[0] - Exit"
	echo "[1] - Begin transaction"
	echo "[2] - Add some information"
    echo "[3] - DEBUG-Encrypt AES something"
    echo "[4] - DEBUG-Decrypt AES something"
    echo "[5] - Set Server address"
    echo "[6] - List blocks in chain"
    echo "[7] - Start bootstrap"
    echo "[8] - List all blocks infos"
    read -p "=>" yn
    case $yn in
        [1]* ) curl -H "Content-type:application/json" --data '{"data" : "information", "publicKey": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n"}' http://$server:3001/auth;;

		[2]* ) curl -H "Content-type:application/json" --data '{"data" : "information", "publicKey": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n", "signature": "ss"}' http://$server:3001/info;;

        [3]* ) curl -H "Content-type:application/json" --data '{"data" : "1234567890123456"}' http://$server:3001/debugEncAES;;

        [4]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/debugDecAES;;

        [5]* ) echo "Inform the server address:"
                read -p "==>" server ;;
        [6]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/listBlocks;;

        [7]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/startBootStrap;;

        [8]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/listInfos;;

        [0]* ) exit;;
        * ) echo "Please answer.";;
    esac
done



#!/bin/bash
server="localhost"
while true; do
    
	echo "Choose your option ["$server"]:"
	echo "[0] - Exit"
	echo "[1] - Begin transaction"
	echo "[2] - Add some information"
    echo "[3] - DEBUG-Encrypt AES something"
    echo "[4] - DEBUG-Decrypt AES something"
    echo "[5] - Set Server address"
    echo "[6] - List blocks in chain"
    echo "[7] - Start bootstrap"
    echo "[8] - List all blocks infos"
    echo "[9] - Add new peer"
    echo "[w] - List peers"
    read -p "=>" yn
    case $yn in
        [1]* ) 
                t1=`date +%s%N`
                curl -H "Content-type:application/json" --data '{"data" : "information", "publicKey": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n"}' http://$server:3001/auth
                t2=`date +%s%N`
                t3=$((t2 - t1))
                tn=$((t3 / 1000000))
                echo "Time in mili to send request: $tn" ;;

		[2]* ) echo "How many requests:"
                read -p "==>" rep 
                i=1 
                while [ "$i" -le "$rep" ] 
                do                    
                    echo "Sending $i request"
                    t1=`date +%s%N`
                    curl -H "Content-type:application/json" --data '{"data" : "information", "publicKey": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n", "signature": "ss"}' http://$server:3001/info
                    t2=`date +%s%N`
                    echo "end $t2"
                    i=$((i + 1 ))
                    t3=$((t2 - t1))
                    tn=$((t3 / 1000000))
                    #echo "Time in nano to send request: $t3"
                    echo "Time in mili to send request: $tn"
                    sleep 1
                done 
                echo "ok" ;;

        [3]* ) curl -H "Content-type:application/json" --data '{"data" : "1234567890123456"}' http://$server:3001/debugEncAES;;

        [4]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/debugDecAES;;

        [5]* ) echo "Inform the server address:"
                read -p "==>" server ;;
        [6]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/listBlocks;;

        [7]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/startBootStrap;;

        [8]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/listInfos;;

        [9]* ) echo "Inform the peer address:"
                read -p "==>" peer
                echo "Inform the peer port:"
                read -p "==>" port
            curl -H "Content-type:application/json" --data '{"host" : "'$peer'", "port" : "'$port'" }' http://$server:3001/addPeer;;

        [w]* ) curl -H "Content-type:application/json" --data '{"data" : "x"}' http://$server:3001/listPeers;;            

        [0]* ) exit;;
        * ) echo "Please answer.";;
    esac
done



#!/bin/bash
screen -wipe
for session in $(screen -ls | grep -o '[0-9]*\.pox'); do screen -S "${session}" -X quit; done
for session in $(screen -ls | grep -o '[0-9]*\.mn'); do screen -S "${session}" -X quit; done
sudo mn -c
./config.sh

screen -S mn -d -m ./run_mininet.sh

screen -S pox -d -m ./run_pox.sh
# waits for the "Ready." message from POX
./pox_expect >/dev/null
echo "POX ready"

echo
echo "*********************************"
echo "Mininet and POX are now started, each in its own screen (with
names mn and pox). You can attach to the Mininet screen with 'screen
-r mn'. See the man page for screen for more details. You can now run
sr. We recommend that you start a new screen session to run sr with
'screen -S sr'. Once you are in the screen session, start the router
with './sr_solution' or './router/sr'. You can then detach from the
screen session and return to your main terminal with Ctrl-a Ctrl-d. To
return to the screen, use 'screen -r sr'. You can kill the session
with Ctrl-d. If you find it more convenient, you can simply start a
new ssh connection, and you will not have to use screen."
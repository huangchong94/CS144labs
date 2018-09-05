USERNAME=`whoami`
HOMEDIR=/home/$USERNAME
CRONLOGNAME=.cron_log
CRONLOG=$HOMEDIR/$CRONLOGNAME
LOGTAR=git_logs.tar.gz
LOGDIR=$HOMEDIR/.cs144

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters"
fi

TARNAME=$1
LABNAME=$2

PRINTF=printf

if [ -a $TARNAME ]; then
    $PRINTF "Removing previous $TARNAME.\n"
    rm -f $TARNAME
fi
# ---------- Ask if student would like to include assignment progress info
$PRINTF "Would you like to include logs of your assignment progress?\n"
$PRINTF "These progress logs will be used for education research purposes.\n"
$PRINTF "They *will not* affect your assignment grade.\n"
$PRINTF "Include assignment progress logs [y/N]:\n"
read ANSWER
if [ "$ANSWER" = "Y" -o "$ANSWER" = "y" -o "$ANSWER" = "yes" ]; then
    $PRINTF "Including assignment progress logs in your submission tar.\n"
    cp $CRONLOG $LOGDIR/$LABNAME/
    tar -C $LOGDIR/ -zcf $LOGTAR $LABNAME
    tar -zcf $TARNAME *.c *.h README Makefile $LOGTAR
    rm $LOGTAR
    rm $LOGDIR/$LABNAME/$CRONLOGNAME
else
    $PRINTF "Excluding assignment progress logs in your submission tar.\n"
    tar -zcf $TARNAME *.c *.h README Makefile
fi

$PRINTF "Created a tarball of your assignment called $TARNAME.\n"

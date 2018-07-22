#!/bin/sh

botresult='/tmp/bot.result.log'

Count="3"

AddFile () {	

	cat $file | grep SRC |  awk -F"=" '{ print $5 }'  | sort -u | sed "s/\ //;s/DST//" > /tmp/check.bot.tmp
}


CheckIP () {

if [ -f $botresult ]; then { /bin/rm -f $botresult; } fi

while read IP 
do
echo "check "$IP >> $botresult
whois $IP | grep -iE "google|yandex"  >> $botresult
#echo $IP

done < /tmp/check.bot.tmp
cat $botresult
}


AddFile
CheckIP

exit 0

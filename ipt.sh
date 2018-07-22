#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
Path=$( cd "$( dirname "$0" )" && pwd )

### Modules load ###
modprobe ip_conntrack_ftp

### IPTables ###
ssh_port="22022"
www_port="80","443"
#dns_port="53"
#ftp_port="21","3306"
#mail_port="25"
pptpd_port="1723"
gre="47"
#"110","143","465","587","993","995"
#echo $true_ip
##############
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i ppp+ -j ACCEPT
ipset flush
## delete chain
ipset -X trueips
ipset -X truenets
ipset -X botipnets
ipset -X badips
ipset -X badnets
ipset -X badipstime
ipset -X badnetstime

## create chain
## true 
ipset -N trueips iphash
ipset -N truenets nethash
ipset -N botipnets nethash

## badips
ipset -N badips iphash
ipset -N badnets nethash
ipset -N badipstime   hash:ip timeout 300
ipset -N badnetstime   hash:net timeout 300




#########  ESTABLISHED
iptables -A INPUT -p all -m state --state RELATED,ESTABLISHED -j ACCEPT


# anti DDoS
#iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT

# antispoofing
iptables -I INPUT -m conntrack --ctstate NEW,INVALID -p tcp --tcp-flags SYN,ACK SYN,ACK -j REJECT --reject-with tcp-reset


########## TRUST
iptables -A INPUT -p all -m state --state RELATED,ESTABLISHED -j ACCEPT
###iptables -A INPUT -s ${bot_ip} -p tcp   -m multiport  --dport ${www_port} -j ACCEPT


######### true_ip

if [ -e "${Path}/true.ip" ] 
then
	while read  true_ip
	do
		if [[ ! $true_ip =~ ^#|^$ ]]
		then	
			ipset -A trueips  ${true_ip}
		fi
	done < ${Path}/true.ip
fi
if [ -e "${Path}/truenets.ip" ] 
then
	while read  true_ip
	do
		if [[ ! $true_ip =~ ^#|^$ ]]
		then	
			ipset -A truenets  ${true_ip}
		fi
	done < ${Path}/truenets.ip
fi

######## Google bot
#if [ -e "${Path}/google.bot.ip" ]
#then
#	while read  true_ip
#	do
#		if [[ ! $true_ip =~ ^#|^$ ]]
#		then	
#			ipset -A botipnets ${true_ip}
#		fi
#	done < ${Path}/google.bot.ip
#fi
######## Yandex bot
#if [ -e "${Path}/yandex.bot.ip" ]
#then
#	while read  true_ip
#	do	
#		if [[ ! $true_ip =~ ^#|^$ ]]
#		then 
#			ipset -A botipnets ${true_ip}
#		fi
#	done < ${Path}/yandex.bot.ip
#fi


######## protection 
######## Bad IP 
if [ -e "${Path}/bad.ip" ]
then
	while read  bad_ip
	do	
		if [[ ! $bad_ip =~ ^#|^$ ]]
		then 
                        ipset -A badips ${bad_ip}
		fi
	done < ${Path}/bad.ip
fi
if [ -e "${Path}/badnets.ip" ]
then
	while read  bad_ip
	do	
		if [[ ! $bad_ip =~ ^#|^$ ]] 
		then 
                        ipset -A badnets ${bad_ip}
		fi
	done < ${Path}/badnets.ip
fi

iptables -A INPUT -m set --match-set trueips  src -j ACCEPT
iptables -A INPUT -m set --match-set truenets  src -j ACCEPT


#iptables -A INPUT  -p tcp -m set --match-set botipnets src  -m multiport  --dport ${www_port} -j ACCEPT

iptables -I INPUT -m set --match-set badips  src -j DROP
iptables -I INPUT -m set --match-set badipstime  src -j DROP
iptables -I INPUT -m set --match-set badnets src -j DROP
iptables -I INPUT -m set --match-set badnetstime src -j DROP

########## SSH
#iptables -A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
#iptables -A fail2ban-ssh -j RETURN

#iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 
#iptables --table nat --append POSTROUTING --out-interface ppp0 -j MASQUERADE

iptables -I INPUT -s  192.168.10.0/24 -i ppp0 -j ACCEPT
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination  185.151.247.27



########## SSH
iptables -A INPUT  -p tcp -m multiport  --dport ${ssh_port}  -m connlimit --connlimit-above 5 -j LOG --log-prefix "iptables: "
iptables -A INPUT  -p tcp -m multiport  --dport ${ssh_port}  -m connlimit --connlimit-above 5 -j REJECT
iptables -A INPUT  -p tcp -m multiport  --dport ${ssh_port} -j ACCEPT

########## PPTP
#iptables -A INPUT  -p tcp -m multiport  --dport ${pptpd_port}  -m connlimit --connlimit-above 30 -j LOG --log-prefix "iptables: "
#iptables -A INPUT  -p tcp -m multiport  --dport ${pptpd_port}  -m connlimit --connlimit-above 30 -j REJECT
#iptables -A INPUT  -p tcp -m multiport  --dport ${pptpd_port} -j ACCEPT
### GRE
#iptables -A INPUT  -p tcp -m multiport --dport ${gre} -j ACCEPT



########## WEB

#iptables -A INPUT  -p tcp -m multiport  --dport ${www_port}  -m connlimit --connlimit-above 75 -j LOG --log-prefix "iptables: "
#iptables -A INPUT  -p tcp -m multiport  --dport ${www_port}  -m connlimit --connlimit-above 75 -j REJECT
iptables -A INPUT  -p tcp -m multiport  --dport ${www_port} -j ACCEPT


########## DNS

#iptables -A INPUT  -p udp -m multiport  --dport ${dns_port}  -m connlimit --connlimit-above 20 -j LOG --log-prefix "iptables: "
#iptables -A INPUT  -p udp -m multiport  --dport ${dns_port}  -m connlimit --connlimit-above 20 -j REJECT
#iptables -A INPUT  -p udp -m multiport  --dport ${dns_port} -j ACCEPT


########## FTP

#iptables -A INPUT  -p tcp -m multiport  --dport ${ftp_port}  -m connlimit --connlimit-above 20 -j LOG --log-prefix "iptables: "
#iptables -A INPUT  -p tcp -m multiport  --dport ${ftp_port}  -m connlimit --connlimit-above 20 -j REJECT
#iptables -A INPUT  -p tcp -m multiport  --dport ${ftp_port} -j ACCEPT

########## MAIL

#iptables -A INPUT  -p tcp -m multiport  --dport ${mail_port}  -m connlimit --connlimit-above 15 -j LOG --log-prefix "iptables: "
#iptables -A INPUT  -p tcp -m multiport  --dport ${mail_port}  -m connlimit --connlimit-above 15 -j REJECT
#iptables -A INPUT  -p tcp -m multiport  --dport ${mail_port} -j ACCEPT



#  ICMP
iptables  -A INPUT -p icmp -j ACCEPT 


echo "Finish !!!"
exit 0

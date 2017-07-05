#!/bin/bash
i=1;
COMMAND_PATH=`pwd`
while true;
do  
	temp=`${COMMAND_PATH}/mbtcp_mstr 10.193.20.66 502`; 
	echo $i:  $temp;  
	((i++));

done

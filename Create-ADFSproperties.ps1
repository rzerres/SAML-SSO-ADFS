$HTTPS_Port_active = (get-adfsproperties).HttpsPort
$HTTPS_Port_target = 8443
$ADFS_ServiceName = adfssrv

netsh http show urlacl
netsh http del urlacl https://+:$HTTPS_Port_active/adfs/
netsh http del urlacl https://+:$HTTPS_Port_active/FederationMetadata/2007-06/

netsh http add urlacl https://+:$HTTPS_Port_target/adfs/ user=”NT SERVICE\adfssrv” delegate=yes
netsh http add urlacl https://+:$HTTPS_Port_target/FederationMetadata/2007-06/ user=”NT SERVICE\adfssrv” delegate=yes

Set-ADFSProperties -HttpsPort $HTTPS_Port_targe

Restart-Service -Name $ADFS_serviceName

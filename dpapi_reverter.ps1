#récupération du mot de passe
& {[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic'); $user_password = [Microsoft.VisualBasic.Interaction]::InputBox('Entrer le mot de passe : ', '');}

echo "Récupération des mots de passe DPAPI" > extract.txt

move .\mimi* $env:TEMP\
cd $env:TEMP

# on récupère le sid de l'utilisateur courant
$siduser = (Get-WmiObject win32_useraccount | Where { $_.name -like "*$env:UserName*" } | select-object -expand sid)

# Pour chaque credential on récupère sa masterkey
Get-ChildItem -Hidden "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Credentials" |
Foreach-Object {

	# on récupère le guid de la masterkey du credential
	$masterkeyguid =  (.\mimikatz.exe "privilege::debug" "log" "dpapi::cred /in:C:\Users\$env:UserName\AppData\Roaming\Microsoft\Credentials\$_" exit) | Out-String -Stream | Select-String "guidMasterKey      :" | %{$_.Line.Replace("guidMasterKey      :","").Replace("{","").Replace("}","")}
	$masterkeyguid = $masterkeyguid.Trim()
	
	# on déchiffre la masterkey avec le mot de passe du compte
	$masterkey =  (.\mimikatz.exe "privilege::debug" "log" "dpapi::masterkey /in:C:\Users\$env:UserName\Appdata\Roaming\Microsoft\Protect\$siduser\$masterkeyguid /sid:$siduser /password:$user_password /unprotect" exit) | Out-String -Stream | Select-String " key :" | %{$_.Line.Replace("key : ","")} 
	$masterkey = $masterkey.Trim()

	# on déchiffre le credential avec la clé de la masterkey
	$cred = (.\mimikatz.exe "privilege::debug" "log" "dpapi::cred /in:C:\Users\$env:UserName\AppData\Roaming\Microsoft\Credentials\$_ /masterkey:$masterkey" exit) | Out-String -Stream 

	$targetname = $cred | Select-String "TargetName" | %{$_.Line.Replace("TargetName","").Replace("{","").Replace("}","")}
	$UserName = $cred | Select-String "UserName" | %{$_.Line.Replace("UserName","").Replace("{","").Replace("}","")}
	$CredentialBlob = $cred | Select-String "CredentialBlob" | %{$_.Line.Replace("CredentialBlob","").Replace("{","").Replace("}","")}

	

	echo "Nouvel identifiant déchiffré :">> extract.txt
	echo "TARGET $targetname">> extract.txt
	echo "USERNAME $UserName">> extract.txt
	echo "MOT DE PASSE $CredentialBlob">> extract.txt
	echo "">> extract.txt
}

notepad extract.txt
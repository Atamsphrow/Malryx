/*
 * Regles YARA de base livrees avec Malryx.
 *
 * Objectif : couvrir des motifs de code malveillant courants sous Linux qui
 * echappent aux signatures de hash (le moindre octet modifie change le hash,
 * pas le motif).
 *
 * Chaque regle porte des meta lues par le moteur :
 *   name        -> nom affiche dans l'UI
 *   severity    -> clean | low | medium | high | critical
 *   description -> explication montree a l'utilisateur
 *
 * Les regles ajoutees par l'utilisateur dans ~/.local/share/malryx/yara/
 * sont chargees en plus de celles-ci, sans reconstruire le paquet.
 */

rule Eicar_Test_File
{
    meta:
        name = "EICAR-Test-File"
        severity = "low"
        description = "Fichier de test antivirus standard. Inoffensif : sert a verifier que le scanner fonctionne."
        author = "Malryx"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Linux_Reverse_Shell_Bash
{
    meta:
        name = "Linux.ReverseShell.Bash"
        severity = "high"
        description = "Script ouvrant un shell vers une machine distante via /dev/tcp."
        author = "Malryx"
    strings:
        $dev_tcp   = "/dev/tcp/" ascii
        $redirect1 = ">&" ascii
        $redirect2 = "0>&1" ascii
        $shell     = /(ba)?sh -i/ ascii
    condition:
        $dev_tcp and ($shell or ($redirect1 and $redirect2))
}

rule Linux_Reverse_Shell_Netcat
{
    meta:
        name = "Linux.ReverseShell.Netcat"
        severity = "high"
        description = "Utilisation de netcat pour exposer un interpreteur de commandes."
        author = "Malryx"
    strings:
        $nc_e     = /nc(\.traditional)? +(-[a-z]* ?)*-e +\/bin\/(ba)?sh/ ascii
        $mkfifo   = "mkfifo /tmp/" ascii
        $nc_pipe  = /nc +[0-9.]+ +[0-9]+/ ascii
    condition:
        $nc_e or ($mkfifo and $nc_pipe)
}

rule Script_Download_And_Execute
{
    meta:
        name = "Script.DownloadExec"
        severity = "high"
        description = "Telecharge du code depuis Internet et l'execute immediatement, sans verification."
        author = "Malryx"
    strings:
        $curl_sh = /curl [^\n|;]{0,200}\| *(ba)?sh/ ascii nocase
        $wget_sh = /wget [^\n|;]{0,200}\| *(ba)?sh/ ascii nocase
        $wget_o  = /wget [^\n]{0,100}-O *(-|\/tmp\/)/ ascii nocase
        $chmod_x = /chmod \+?x/ ascii
    condition:
        $curl_sh or $wget_sh or ($wget_o and $chmod_x)
}

rule PHP_Webshell_Eval
{
    meta:
        name = "PHP.Webshell.Eval"
        severity = "critical"
        description = "Porte derobee PHP : execute du code recu par la requete HTTP."
        author = "Malryx"
    strings:
        $php     = "<?php" ascii
        $eval_b64 = /eval *\( *base64_decode *\(/ ascii nocase
        $req_exec = /(system|exec|shell_exec|passthru|popen) *\( *\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        $eval_req = /eval *\( *\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        $preg_e   = /preg_replace *\( *['"].*\/e['"]/ ascii nocase
    condition:
        $php and ($eval_b64 or $req_exec or $eval_req or $preg_e)
}

rule Python_Obfuscated_Payload
{
    meta:
        name = "Python.Obfuscated.Exec"
        severity = "medium"
        description = "Code Python qui decode puis execute une charge utile dissimulee."
        author = "Malryx"
    strings:
        $b64_exec  = /exec *\( *(base64|codecs|zlib|marshal)\./ ascii
        $b64_eval  = /eval *\( *(base64|codecs|zlib|marshal)\./ ascii
        $import_d  = "__import__" ascii
        $decode    = "b64decode" ascii
    condition:
        $b64_exec or $b64_eval or ($import_d and $decode)
}

rule ELF_Packed_UPX
{
    meta:
        name = "ELF.Packed.UPX"
        severity = "low"
        description = "Binaire ELF compresse avec UPX. Legitime en soi, mais couramment utilise pour masquer un executable."
        author = "Malryx"
    strings:
        $upx0 = "UPX!" ascii
        $upx1 = "$Info: This file is packed with the UPX" ascii
    condition:
        uint32(0) == 0x464C457F and ($upx0 or $upx1)
}

rule Linux_Persistence_Cron
{
    meta:
        name = "Linux.Persistence.Cron"
        severity = "medium"
        description = "Script installant une tache planifiee pour se relancer automatiquement."
        author = "Malryx"
    strings:
        $crontab   = /crontab +-/ ascii
        $cron_dir  = "/etc/cron.d/" ascii
        $reboot    = "@reboot" ascii
        $curl_wget = /(curl|wget) /  ascii nocase
    condition:
        ($crontab or $cron_dir or $reboot) and $curl_wget
}

rule Linux_AntiForensics_HistoryWipe
{
    meta:
        name = "Linux.AntiForensics.HistoryWipe"
        severity = "medium"
        description = "Tente d'effacer les traces de son passage (historique, journaux)."
        author = "Malryx"
    strings:
        $hist1 = "unset HISTFILE" ascii
        $hist2 = "history -c" ascii
        $hist3 = "export HISTSIZE=0" ascii
        $wipe  = /rm +-rf? +[^\n]{0,40}\/var\/log/ ascii
        $shred = /shred +-/ ascii
    condition:
        2 of them
}

rule Crypto_Miner_Config
{
    meta:
        name = "CoinMiner.Config"
        severity = "high"
        description = "Configuration de mineur de cryptomonnaie : consomme les ressources de la machine a l'insu de son proprietaire."
        author = "Malryx"
    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $xmrig = "xmrig" ascii nocase
        $donate = "donate-level" ascii nocase
        $algo  = "randomx" ascii nocase
    condition:
        $pool1 or $pool2 or ($xmrig and ($donate or $algo))
}

rule Windows_Executable_On_Removable
{
    meta:
        name = "Windows.Autorun.Dropper"
        severity = "medium"
        description = "Fichier autorun designant un executable : mecanisme classique de propagation par cle USB."
        author = "Malryx"
    strings:
        $autorun = "[autorun]" ascii nocase
        $open    = /open *= *[^\n]{1,120}\.(exe|cmd|bat|scr|com|pif)/ ascii nocase
        $shellex = /shell\\[^\n]{0,40}\\command *=/ ascii nocase
    condition:
        $autorun and ($open or $shellex)
}

<?php
$fh = fopen('php://stdin', 'r');
$cmd = '';
$bcLvl = 0;
while (true)
{
    $line = rtrim(fgets($fh));
    $bcLvl += substr_count($line, '{') - substr_count($line, '}');
    $cmd.= $line;
    if ($bcLvl > 0 or substr($cmd, -1) !== ';')
    continue;
    eval($cmd);
    $cmd = '';
}
?>

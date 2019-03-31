# Ohjelman käyttöohje

## Sovelluksen sijainti
TODO

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
muotoiseksi tiedoksi ja `file` salaa/purkaa tiedostosta tiedostoon. Lopussa
annettavat tiedot riippuvat juuri tästä tilasta.

Tämän jälkeen annetaan salausalgoritmiksi joko `DES`, `3DES` tai `AES`.
Ensimmäinen odottaa 56- tai 64-bittistä avainta, toinen joko 112-, 128-,
168- tai 192-bittistä avainta ja kolmas joko 128-, 192- tai 256-bittistä
avainta. Jos alustusvektori määritellään, sen on oltava 64-bittinen
`DES` ja `3DES` -algoritmeilla sekä 128-bittinen `AES`-algoritmilla.

Algoritmin jälkeen määritellään lohkotilaksi joko `ECB`, `CBC` tai `CTR`.
Kaksi viimeistä vaativat myös heti perään alustusvektorin heksamuodossa,
jos avain annetaan myös heksamuodossa. Jos alustusvektorin kohdalle laitetaan 
`-`, salausta tai purkua varten luodaan satunnainen alustusvektori. Tämä
tehdään myös automaattisesti salasanaa käyttäessä, jolloin salatun
tiedon alkuun sijoitetaan satunnaisesti luotu alustusvektori.
Jos `-key`:lle annetaan tiedosto, sen oletetaan sisältävän myös
alustusvektori.

Tämän jälkeen annetaan `-key`, jonka jälkeen annetaan joko avain heksa-
muodossa, salasana (lainausmerkeissä) tai tiedostonimi. Jos tiedostonimi 
annetaan, sen oletetaan sisältävän _aluksi sopivan kokoisen alustusvektorin_
_ja sen jälkeen sopivan kokoisen avaimen_ (huomaa järjestys). Jos salasana 
annetaan, satunnainen alustusvektori sisällytetään salatun tiedon alkuun
ja luetaan sen alusta purettaessa.

Tämän jälkeen tilasta riippuen annetaan syöte ja tuloste. `asc`-tilassa
syötteeksi voi antaa salattavan tai purettavan merkkijonon, mutta jos sitä
ei anneta, ohjelma lukee tietoa standardisyötteestä. `hex`-tilassa syöte
tulee tarjota heksamuodossa. `file`-tilassa tulee tarjota sekä syötetiedoston
nimi että tulostetiedoston nimi.

## `-test`
TODO

# Esimerkkejä
Kaikkien näiden alkuun kuuluu komennon merkkijono, eli esimerkiksi
`java -jar kryptoa.jar -enc `...

* `-enc hex DES ECB -key 853F31351E51CD9C 0A0F2CB1BEFE1D00`
  * Salaa annetun heksamuotoisen syötteen `0A0F2CB1BEFE1D00` DES-algoritmilla
    käyttäen ECB-lohkotilaa ja avaimena `853F31351E51CD9C`.
* `-dec asc AES CTR -key "testi"`
  * Purkaa standardisyötteestä saatavaa tietoa AES-algoritmilla CTR-
    lohkotilalla, käyttäen avaimena `testi`-salasanasta luotua avainta
    ja alustusvektorina tiedon alussa säilöttävää alustusvektoria.
* `-enc file 3DES CBC -key file.key file.zip file.zip.tds`
  * Salaa tiedoston `file.zip` tiedostosta `file.key` löytyvällä
    avaimella ja alustusvektorilla tiedostoon `file.zip.tds`. Käytettävänä
    algoritmina on 3DES eli Triple-DES ja lohkotilana CBC.
* `-enc hex AES CBC 55555555555555555555555555555555 `
  `-key AA9DCA3BA4DE72155C652AE17CFA6926CFD12ADDBB2B212C 00`
  * Salaa yhden 0-tavun AES-algoritmilla ja CBC-lohkotilalla, missä
    alustusvektori on `55555555555555555555555555555555` ja avain on
    `AA9DCA3BA4DE72155C652AE17CFA6926CFD12ADDBB2B212C` (192 bittiä).
* `-test `... TODO

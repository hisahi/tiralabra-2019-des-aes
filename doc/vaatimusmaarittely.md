# Toteutetut algoritmit
Työssä toteutetaan DES, Triple-DES sekä AES. DES:lle toteutetaan kaksi eri lohkosalausmoodia (ECB (Electronic Code Book) ja CBC (Cipher Block Chaining)) ja AES:lle kolme (ECB, CBC ja lisäksi CTR (Counter)). Kyseiset algoritmit vaativat omia tietorakenteitaan, kuten niin kutsutut S-box-rakenteet (mahdollisesti toteutettavissa vain taulukkoina).

# Tarkoitus
Työn tarkoituksena on vertailla erilaisia salausalgoritmeja, tarkalleen ottaen DES-, Triple-DES- (3DES) sekä AES-algoritmeja. Vertailukohteina ovat muun muassa nopeus, toteutus ja muistin käyttö. Koodissa on yritetty ottaa myöskin huomioon mahdolliset sivukanavat, kuten ajoitukset (varmistaa, ettei ajoitus riipu syötteen sisällöstä, koska se voi paljastaa salaista tietoa). Valitsin kyseiset algoritmit siksi, että ne ovat olleet aikanaan standardeja (AES yhä on) ja niitä käytettiin tai käytetään hyvin laajasti. AES on yhä tänäkin päivänä vahvana pidetty salausmenetelmä.

# Syöte ja tuloste
Ohjelma ottaa syötteeksi seuraavaa:

* Valinta siitä, salataanko vai puretaanko.
* Valinta algoritmille: joko DES, Triple-DES tai AES, ja lisäksi tila, jolla salataan: ECB, CBC tai CTR (viimeinen vain AES), ja AES:n tapauksessa avaimen koko: 128, 192 tai 256 bittiä.
* Avain, jonka pituus on 56 bittiä DES-algoritmilla, 168 bittiä Triple-DES-algoritmilla ja 128, 192 tai 256 bittiä AES-algoritmilla (valittavissa).
  * Alustusvektori on 64 bittiä DES- tai Triple-DES-algoritmilla ja 128 bittiä AES-algoritmilla.
* Jos salataan:
  * Mikä tahansa syöte, jonka pituus on vähintään yksi tavu. Kyseinen syöte salataan.
* Jos puretaan:
  * Alustusvektori (IV), jonka pituus on 64 bittiä DES- tai Triple-DES-algoritmilla ja 128 bittiä AES-algoritmilla.
  * Mikä tahansa syöte, jonka pituus on vähintään yksi tavu. Kyseisen syötteen salaus puretaan.

Tulosteena on syöte, kun se on salattu tai sen salaus purettu. Salattaessa ohjelma myös luo alustusvektorin, jota pitää käyttää purkaessa. Jos salattavaan tietoon sovelletaan PKCS#5 ja PKCS#7 -täytemenetelmiä (riippuen lohkon koosta eli algoritmista).

Ohjelman oletustilana on toimia stdin- ja stdout-menetelmällä, jossa parametrit asetetaan käyttämällä lippuja. Tämän lisäksi ohjelmaan toteutetaan testitila, joka salaa kaikilla algoritmeilla ja mittaa nopeudet sekä muistinkäytön.

# Tavoite
Tilavaativuus on O(1), sillä muistissa ei jouduta pitämään syötteen koosta riippuvaa määrää tietoa. Aikavaativuus on O(n), missä n on syötteessä olevien lohkojen lukumäärä.

Vaativuus ei tosin ole merkittävänä tavoitteena vaan varsinainen nopeus. Nopeutta voidaan verrata olemassaolevien ja oikeasti luotettavien salausohjelmien nopeuteen.

# Lähteet
* [FIPS PUB 46-3: Data Encryption Standard](http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf)
* [NIST Special Publication 800-67 Revision 2: Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf)
* [FIPS PUB 197: Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)



